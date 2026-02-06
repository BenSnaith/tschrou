#include "security/security_module.h"

#include <sstream>

namespace tsc::sec {
std::string SecurityPolicy::MetricsToJSON() const {
  auto all = GetAllMetrics();

  std::ostringstream oss;
  oss << "{\"modules\":[";

  for(size_t i{}; i < all.size(); ++i) {
    if (i > 0) oss << ",";

    const auto& mi = all[i];
    oss << "{\"name\":\"" << mi.module_name << "\",\"counters\":{";

    for (size_t j{}; j < mi.counters.size(); ++j) {
      if (j > 0) oss << ",";
      oss << "\"" << mi.counters[j].first << "\":" << mi.counters[j].second;
    }

    oss << "},\"gauges\":{";

    for (size_t j{}; j < mi.gauges.size(); ++j) {
      if (j > 0) oss << ",";
      oss << "\"" << mi.gauges[j].first << "\":" << mi.gauges[j].second;
    }

    oss << "}}";
  }

  oss << "}}";
  return oss.str();
}
} // namespace tsc::sec
