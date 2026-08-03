#include <memory>
#include <stdexcept>
#include <vector>

static int initialized;

struct Startup {
  Startup() { initialized = 11; }
};

static Startup startup;

extern "C" __declspec(dllexport) int cpp_exported(void) {
  std::vector<int> values{1, 2, 3};
  auto allocated = std::make_unique<int>(8);
  int caught = 0;
  try {
    throw std::runtime_error("expected");
  } catch (const std::exception &) {
    caught = 17;
  }
  return initialized + values[0] + values[1] + values[2] + *allocated + caught;
}
