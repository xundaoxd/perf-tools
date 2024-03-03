#include <linux/perf_event.h>
#include <stdexcept>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <system_error>
#include <unistd.h>
#include <unordered_map>
#include <vector>

struct PerfEvent {
  int pid;
  int cpu;
  std::string event;

  int fd;
  std::size_t buf_size;
  char *buf_addr;

  ~PerfEvent() {
    if (buf_addr != MAP_FAILED) {
      munmap(buf_addr, buf_size);
    }
    if (fd != -1) {
      close(fd);
    }
  }
  PerfEvent() {
    pid = -1;
    cpu = -1;
    fd = -1;
    buf_size = 17 * getpagesize();
    buf_addr = (char *)MAP_FAILED;
  }

  void Reset() { ioctl(fd, PERF_EVENT_IOC_RESET, 0); }
  void Enable(bool reset = true) {
    if (reset) {
      Reset();
    }
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  }
  void Disable() { ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
  void Proc() {
    struct perf_event_mmap_page *info = (struct perf_event_mmap_page *)buf_addr;
    while (info->data_tail < info->data_head) {
      struct perf_event_header *header =
          (struct perf_event_header *)(buf_addr + info->data_offset +
                                       (info->data_tail % info->data_size));
      switch (header->type) {
      case PERF_RECORD_SAMPLE: {
        std::uint64_t *fields = (std::uint64_t *)(header + 1);
        std::cout << event << "\t" << pid << "\t" << fields[0] << '\n';
      } break;
      default: {
        std::cout << "unknown type " << header->type << std::endl;
      } break;
      }
      info->data_tail += header->size;
    }
  }
};

bool running{true};
std::string tracefs("/sys/kernel/tracing");

std::uint64_t GetEventId(const std::string &e) {
  std::string path = tracefs + "/events";
  for (auto beg = e.begin(), end = e.end(); beg != end;) {
    auto it = std::find(beg, end, ':');
    path += "/" + e.substr(beg - e.begin(), it - beg);
    beg = it;
  }
  path += "/id";
  std::ifstream ifs(path);
  std::uint64_t id;
  ifs >> id;
  return id;
}

void InitPerfEvents(std::vector<std::unique_ptr<PerfEvent>> &pevents, int argc,
                    char *argv[]) {
  std::vector<std::string> common_flags;
  int idx = 1;
  while (strcmp(argv[idx], "--pid") != 0) {
    common_flags.emplace_back(argv[idx++]);
  }
  for (; idx < argc;) {
    assert(strcmp(argv[idx], "--pid") == 0);
    int pid = std::stoi(argv[idx + 1]);
    idx += 2;
    std::vector<std::string> pflags = common_flags;
    while (idx < argc && strcmp(argv[idx], "--pid") != 0) {
      pflags.emplace_back(argv[idx++]);
    }
    for (auto idx = 0ul; idx < pflags.size();) {
      assert(pflags[idx] == "-e");

      std::unique_ptr<PerfEvent> e = std::make_unique<PerfEvent>();
      e->event = pflags[idx + 1];
      idx += 2;
      e->pid = pid;

      struct perf_event_attr pe;
      memset(&pe, 0, sizeof(pe));
      pe.size = sizeof(pe);

      static std::unordered_map<std::string, perf_hw_id> hw_events{
          {"PERF_COUNT_HW_CPU_CYCLES", PERF_COUNT_HW_CPU_CYCLES},
          {"PERF_COUNT_HW_INSTRUCTIONS", PERF_COUNT_HW_INSTRUCTIONS},
          {"PERF_COUNT_HW_CACHE_REFERENCES", PERF_COUNT_HW_CACHE_REFERENCES},
          {"PERF_COUNT_HW_CACHE_MISSES", PERF_COUNT_HW_CACHE_MISSES},
          {"PERF_COUNT_HW_BRANCH_INSTRUCTIONS",
           PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
          {"PERF_COUNT_HW_BRANCH_MISSES", PERF_COUNT_HW_BRANCH_MISSES},
          {"PERF_COUNT_HW_BUS_CYCLES", PERF_COUNT_HW_BUS_CYCLES},
          {"PERF_COUNT_HW_STALLED_CYCLES_FRONTEND",
           PERF_COUNT_HW_STALLED_CYCLES_FRONTEND},
          {"PERF_COUNT_HW_STALLED_CYCLES_BACKEND",
           PERF_COUNT_HW_STALLED_CYCLES_BACKEND},
          {"PERF_COUNT_HW_REF_CPU_CYCLES", PERF_COUNT_HW_REF_CPU_CYCLES},
      };
      static std::unordered_map<std::string, perf_sw_ids> sw_events{
          {"PERF_COUNT_SW_CPU_CLOCK", PERF_COUNT_SW_CPU_CLOCK},
          {"PERF_COUNT_SW_TASK_CLOCK", PERF_COUNT_SW_TASK_CLOCK},
          {"PERF_COUNT_SW_PAGE_FAULTS", PERF_COUNT_SW_PAGE_FAULTS},
          {"PERF_COUNT_SW_CONTEXT_SWITCHES", PERF_COUNT_SW_CONTEXT_SWITCHES},
          {"PERF_COUNT_SW_CPU_MIGRATIONS", PERF_COUNT_SW_CPU_MIGRATIONS},
          {"PERF_COUNT_SW_PAGE_FAULTS_MIN", PERF_COUNT_SW_PAGE_FAULTS_MIN},
          {"PERF_COUNT_SW_PAGE_FAULTS_MAJ", PERF_COUNT_SW_PAGE_FAULTS_MAJ},
          {"PERF_COUNT_SW_ALIGNMENT_FAULTS", PERF_COUNT_SW_ALIGNMENT_FAULTS},
          {"PERF_COUNT_SW_EMULATION_FAULTS", PERF_COUNT_SW_EMULATION_FAULTS},
          {"PERF_COUNT_SW_DUMMY", PERF_COUNT_SW_DUMMY},
          {"PERF_COUNT_SW_BPF_OUTPUT", PERF_COUNT_SW_BPF_OUTPUT},
          {"PERF_COUNT_SW_CGROUP_SWITCHES", PERF_COUNT_SW_CGROUP_SWITCHES},
      };
      if (hw_events.count(e->event)) {
        pe.type = PERF_TYPE_HARDWARE;
        pe.config = hw_events.at(e->event);
      } else if (sw_events.count(e->event)) {
        pe.type = PERF_TYPE_SOFTWARE;
        pe.config = sw_events.at(e->event);
      } else {
        pe.type = PERF_TYPE_TRACEPOINT;
        pe.config = GetEventId(e->event);
      }

      pe.disabled = 1;
      pe.exclude_kernel = 1;
      pe.exclude_hv = 1;
      pe.exclude_guest = 1;

      pe.sample_period = 1;
      pe.wakeup_events = 1;
      pe.sample_type = PERF_SAMPLE_TIME;

      while (idx < pflags.size() && pflags[idx] != "-e") {
        if (pflags[idx] == "--period") {
          pe.sample_period = std::stoul(pflags[idx + 1]);
          idx += 2;
        } else {
          throw std::runtime_error("unknown event flag " + pflags[idx]);
        }
      }

      e->fd = syscall(SYS_perf_event_open, &pe, e->pid, e->cpu, -1,
                      PERF_FLAG_FD_CLOEXEC);
      if (e->fd == -1) {
        throw std::system_error(errno, std::generic_category());
      }
      e->buf_addr = (char *)mmap(0, e->buf_size, PROT_READ | PROT_WRITE,
                                 MAP_SHARED, e->fd, 0);
      if (e->buf_addr == MAP_FAILED) {
        throw std::system_error(errno, std::generic_category());
      }

      pevents.emplace_back(std::move(e));
    }
  }
}

int main(int argc, char *argv[]) {
  std::signal(SIGINT, [](int) { running = false; });
  std::signal(SIGTERM, [](int) { running = false; });

  std::vector<std::unique_ptr<PerfEvent>> pevents;
  InitPerfEvents(pevents, argc, argv);

  std::vector<struct epoll_event> events(pevents.size());
  int epollfd = epoll_create1(EPOLL_CLOEXEC);
  for (auto &pe : pevents) {
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = pe.get();
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, pe->fd, &ev) == -1) {
      throw std::system_error(errno, std::generic_category());
    }
    pe->Enable();
  }
  while (running) {
    int nfds = epoll_pwait(epollfd, events.data(), events.size(), -1, nullptr);
    if (nfds == -1) {
      throw std::system_error(errno, std::generic_category());
    }
    for (int i = 0; i < nfds; i++) {
      ((PerfEvent *)events[i].data.ptr)->Proc();
    }
  }
  for (auto &pe : pevents) {
    pe->Disable();
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, pe->fd, nullptr) == -1) {
      throw std::system_error(errno, std::generic_category());
    }
  }
  close(epollfd);
  return 0;
}
