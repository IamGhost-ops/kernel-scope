# Project Roadmap & TODO 

This document tracks planned features, improvements, and known issues. Feel free to open an Issue or PR to pick up any of tasks below!


## High priority (Next Release- v0.6.0)

*Tasks that are critical fore core  stability or missing MVP funcionality.*

- [ ] **External YAML Configuration:** Move hardcoded configurations and detection rules out of the agent codebase into an external YAML data into an external 
      YAML file. 
- [ ] **Import Mechanism:** Implement a Python-based ingestion mechanism to fetch, parse, and import the external YAML data into the agent's runtime memory
- [ ] **Automated Certificate Enrollment:** Implement an automated onboarding workflow where the Python agent automatically request and receives its PEM certificates /keys upon first installation (bootstrap phase) without manual user intervetion.
- [ ] **Secure API Endpoint for Keys: Create a dedicated, secure endpoint on your management server to handle  uthentication and issue valid PEM keys/certificates to authorized agents.


## Medium Priority (Backlog)

*Important features and code  health improvments that can wait.*

- [ ] **Secure Ingestion & Exception Handling:** Implement robust error handling and input validation during the YAML parsing process to ensure agent stability and prevent tampetring or crashes.
- [ ] 
- [ ]


## Low Priority & Ideas (Future / Nice-to-Have)

*Experimental ideas, optimizations, and non-blocking tasks.*

- [ ] **Dynamic Reload & Profile Management: Enable hot-reloading of the YAML configuration without restarting the agent process, and support fetching dedicated YAML profiles based on endpoint criteria. 
- [ ] 
- [ ]


## Completed Tasks (Changelog)
*A palce to celebrate progress and keep track of what already works.*

- [ ]
- [ ]
- [ ]
- [ ]
