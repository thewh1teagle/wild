#include <cstdio>
#include <memory>
#include <stdexcept>
#include <vector>

static int initialized;

struct Startup {
  Startup() { initialized = 11; }
};

static Startup startup;

int main() {
  std::vector<int> values{1, 2, 3};
  auto allocated = std::make_unique<int>(8);
  int caught = 0;
  try {
    throw std::runtime_error("expected");
  } catch (const std::exception &) {
    caught = 17;
  }

  std::printf("wild-pe-cpp-runtime %d\n",
              initialized + values[0] + values[1] + values[2] + *allocated + caught);
  return 62;
}
