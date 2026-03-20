#include "node/node.h"
#include "util/hash.h"
#include "types/types.h"
#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <csignal>

using namespace tsc;

// Global node pointer for signal handling
node::Node* g_node = nullptr;

void signal_handler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down...\n";
    if (g_node) {
        g_node->Shutdown();
    }
    exit(0);
}

void print_usage(const char* program) {
    std::cout << "Usage:\n"
              << "  " << program << " create <port>              - Create a new ring\n"
              << "  " << program << " join <port> <known_ip:port> - Join existing ring\n"
              << "\nExample:\n"
              << "  " << program << " create 8000\n"
              << "  " << program << " join 8001 127.0.0.1:8000\n";
}

void print_help() {
    std::cout << "\nAvailable commands:\n"
              << "  put <key> <value>  - Store a key-value pair\n"
              << "  get <key>          - Retrieve a value\n"
              << "  state              - Show node state\n"
              << "  fingers            - Show finger table\n"
              << "  hash <string>      - Show hash of a string\n"
              << "  help               - Show this help\n"
              << "  quit               - Leave the ring and exit\n\n";
}

void run_interactive(node::Node& node) {
    print_help();

    std::string line;
    while (true) {
        std::cout << "chord> ";
        std::cout.flush();

        if (!std::getline(std::cin, line)) {
            break;
        }

        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;

        if (cmd.empty()) {
            continue;
        }

        if (cmd == "quit" || cmd == "exit") {
            std::cout << "Leaving ring...\n";
            node.Leave();
            break;
        }
        else if (cmd == "help") {
            print_help();
        }
        else if (cmd == "state") {
            node.PrintState();
        }
        else if (cmd == "fingers") {
            node.PrintFingerTable();
        }
        else if (cmd == "put") {
            std::string key, value;
            iss >> key;
            std::getline(iss, value);

            // Trim leading space from value
            if (!value.empty() && value[0] == ' ') {
                value = value.substr(1);
            }

            if (key.empty() || value.empty()) {
                std::cout << "Usage: put <key> <value>\n";
                continue;
            }

            if (node.Put(key, value)) {
                std::cout << "Stored: " << key << " -> " << value << "\n";
                std::cout << "(Key ID: " << hsh::Hash::HashKey(key) << ")\n";
            } else {
                std::cout << "Failed to store key\n";
            }
        }
        else if (cmd == "get") {
            std::string key;
            iss >> key;

            if (key.empty()) {
                std::cout << "Usage: get <key>\n";
                continue;
            }

            auto value = node.Get(key);
            if (value) {
                std::cout << key << " -> " << *value << "\n";
            } else {
                std::cout << "Key not found\n";
            }
        }
        else if (cmd == "hash") {
            std::string str;
            iss >> str;

            if (str.empty()) {
                std::cout << "Usage: hash <string>\n";
                continue;
            }

            std::cout << "hash(\"" << str << "\") = " << hsh::Hash::ComputeHash(str) << "\n";
        }
        else {
            std::cout << "Unknown command: " << cmd << "\n";
            std::cout << "Type 'help' for available commands\n";
        }
    }
}

void parse_flags(int argc, char* argv[], int start_idx, node::Node::Config& config) {
  for (int i = start_idx; i < argc; ++i) {
    std::string flag = argv[i];

    // Security flags
    if (flag == "--id-verify")           config.enable_id_verification = true;
    else if (flag == "--subnet-diversity") config.enable_subnet_diversity = true;
    else if (flag == "--rate-limit")      config.enable_rate_limiting = true;
    else if (flag == "--lookup-validate")  config.enable_lookup_validation = true;
    else if (flag == "--peer-age")         config.enable_peer_age = true;
    else if (flag == "--honeypot")         config.enable_honeypot = true;
    else if (flag == "--all-security") {
      config.enable_id_verification = true;
      //config.enable_subnet_diversity = true;
      config.enable_rate_limiting = true;
      config.enable_lookup_validation = true;
      config.enable_peer_age = true;
      config.enable_honeypot = true;
    }

    else if (flag == "--malicious")        config.is_malicious = true;
    else if (flag == "--ip" && i + 1 < argc) config.ip_ = argv[++i];

    else if (flag == "--subnet-max" && i + 1 < argc) config.subnet_max_per = std::stoi(argv[++i]);
    else if (flag == "--rl-tokens" && i + 1 < argc)  config.rate_limit_max_tokes = std::stoi(argv[++i]);
    else if (flag == "--rl-refill" && i + 1 < argc)  config.rate_limit_refill = std::stod(argv[++i]);
    else if (flag == "--lv-checks" && i + 1 < argc)  config.lookup_validation_checks = std::stoi(argv[++i]);
    else if (flag == "--age-min" && i + 1 < argc)    config.peer_age_min_seconds = std::stod(argv[++i]);
    else if (flag == "--hp-count" && i + 1 < argc)   config.honeypot_count = std::stoi(argv[++i]);
  }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];
    auto port = static_cast<type::u16>(std::stoi(argv[2]));


    int flags_start = (mode == "join") ? 4 : 3;
    node::Node::Config config;
    config.ip_ = "127.0.0.1";
    config.port_ = port;
    parse_flags(argc, argv, flags_start, config);

    if (config.is_malicious) {
      std::cout << "[MALICIOUS] Node running in malicious mode at "
                << config.ip_ << ":" << config.port_ << "\n";
    }

    node::Node node(config);
    g_node = &node;

    // Set up signal handlers
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    bool success = false;

    if (mode == "create") {
        success = node.Create();
    }
    else if (mode == "join") {
        if (argc < 4) {
            std::cerr << "Error: join requires known node address\n";
            print_usage(argv[0]);
            return 1;
        }

        // Parse known_ip:port
        std::string known = argv[3];
        size_t colon = known.find(':');
        if (colon == std::string::npos) {
            std::cerr << "Error: invalid address format. Use ip:port\n";
            return 1;
        }

        type::NodeAddress known_node;
        known_node.ip_ = known.substr(0, colon);
        known_node.port_ = static_cast<uint16_t>(std::stoi(known.substr(colon + 1)));

        success = node.Join(known_node);
    }
    else {
        std::cerr << "Unknown mode: " << mode << "\n";
        print_usage(argv[0]);
        return 1;
    }

    if (!success) {
        std::cerr << "Failed to start node\n";
        return 1;
    }

    // Give stabilization a moment to run
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Run interactive shell
    run_interactive(node);

    return 0;
}
