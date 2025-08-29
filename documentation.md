### Project Documentation: The Compliance Sentinel

This document outlines the architecture, workflow, and technical requirements for the "Compliance Sentinel," a project designed to showcase the power of Kiro's agentic capabilities. The goal is to create a proactive, automated system that enforces security and compliance policies within a codebase in real-time.

### 1. Project Overview and Core Philosophy

The Compliance Sentinel is not a traditional static analysis tool; it's an intelligent, self-managing system built on Kiro's agentic features. Instead of relying on manual code reviews or post-development checks, this project integrates compliance directly into the development workflow. The core philosophy is to shift security from a reactive process to a proactive, automated one, where the AI serves as a vigilant partner that ensures every line of code meets predefined standards and policies.[1, 2, 3]

### 2. The Agentic Workflow: A Step-by-Step Process

The project operates on a simple, but powerful, closed-loop system driven by Kiro's core features.

1.  **Define the Policy (Agent Steering):** The project's intelligence begins with a central policy document. A markdown file named `security.md` is created in the project's `.kiro/steering/` directory.[3, 4, 5] This file serves as the single source of truth for all compliance and security rules. Kiro's agents are trained to reference this document as part of their persistent project context, ensuring all code generation and analysis adhere to these rules.[3]

    *   **Example Content for `.kiro/steering/security.md`:**
        *   `Rule 1: All API endpoints must implement authentication and rate-limiting policies.`
        *   `Rule 2: Never hardcode sensitive credentials. All secrets must be loaded from environment variables.`
        *   `Rule 3: Use of external libraries must be validated against a list of known vulnerabilities from a real-time CVE database.`

2.  **Automate the Enforcement (Agent Hooks):** The rules defined in the steering file are enforced through Kiro's Agent Hooks.[2, 6, 7] A hook is an event-driven automation that triggers a specific action based on an event, such as saving a file or a pre-commit command.[6, 8, 9] The Compliance Sentinel configures a hook to run a security scan every time a relevant file is modified. This turns a manual, mental checklist into an automated, background process that catches issues as they are introduced.[2, 10]

3.  **Integrate External Intelligence (Model Context Protocol - MCP):** To ensure the security checks are up-to-date and accurate, a custom Model Context Protocol (MCP) server is required.[11, 12, 13] This server acts as a secure intermediary, allowing Kiro's agents to connect to and query external data sources without exposing sensitive project data.[11, 14] For this project, the MCP server would be configured to connect to a real-time vulnerability database or a regulatory API.

4.  **The Proactive Feedback Loop:** When a developer saves a file, the Agent Hook is triggered.[6] Kiro's agent receives the request and, in its reasoning loop, analyzes the new code against the rules in `security.md`.[15] Simultaneously, it uses the custom MCP server to query the external vulnerability database for any issues related to the project's dependencies or code patterns.[12, 15] The agent then provides immediate feedback in the IDE, flagging the issue, explaining the violation, and suggesting a fix, all before the code is committed.[15]

### 3. Technical Requirements and Programming Stack

*   **Programming Language:** **Python** is the recommended language for this project due to its robust ecosystem and native support within Kiro.[16, 17] This choice facilitates the creation of both the main application and the custom MCP server.

*   **Key Modules & Libraries:** The project relies on a collection of open-source libraries to perform its core functions.

    *   **For the Custom MCP Server:**
        *   **`FastAPI`:** A modern, high-performance web framework for building APIs.[18, 19]
        *   **`fastapi-mcp`:** An open-source tool that simplifies the process of converting FastAPI routes into Kiro-compatible MCP tools with minimal code.[18, 20]

    *   **For Static Application Security Testing (SAST):**
        *   **`Bandit`:** A lightweight, open-source tool specifically designed to find common security issues in Python code.[21, 22] It scans code for known patterns of insecurity, such as the use of insecure cryptography or hardcoded secrets.[22]
        *   **`Semgrep`:** A powerful static analysis tool that can be used to write custom rules for security policies.[23] It can be configured to find issues like hardcoded credentials and other security vulnerabilities.[23]
        *   **`SonarQube`:** A comprehensive static analysis tool that can identify bugs, code smells, and security vulnerabilities.[24, 25]

    *   **For Dependency Vulnerability Scanning:**
        *   **`OWASP Dependency-Check`:** A Software Composition Analysis (SCA) tool that detects publicly disclosed vulnerabilities in a project's dependencies.[26, 27] It scans files like `requirements.txt` and compares them against databases like the National Vulnerability Database (NVD).[27]

### 4. Python Version Selection: 3.13 vs. 3.11

The choice of Python version for a new project involves a trade-off between stability and access to the latest features.

*   **Python 3.11:** This version offers long-term support until October 2027.[28] It introduced significant performance improvements and new features for asynchronous programming, such as `TaskGroup`.[29] For a production-ready system where stability and broad library compatibility are paramount, Python 3.11 is a solid and reliable choice .

*   **Python 3.13:** As a newer version, Python 3.13 includes several experimental features, such as a Just-in-Time (JIT) compiler and the ability to run in a free-threaded mode (disabling the GIL) . These features can offer performance benefits, but their experimental nature means they should be used with caution . While over half of the top PyPI packages support 3.13, a significant portion (41.9%) do not explicitly, which could lead to compatibility issues with project dependencies .

For a project like the Compliance Sentinel, which is intended to be a robust, long-term solution, **Python 3.11** is the more prudent choice. It provides the stability and wide-ranging library support necessary for a mission-critical application. However, for a hackathon entry specifically focused on showcasing the cutting edge of Python development, using the experimental features of **Python 3.13** could be a strong strategic move to demonstrate innovation .