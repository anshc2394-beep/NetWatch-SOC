# NetWatch-SOC — Development Notes
 - A .env file stores config information that your application needs such as: API Keys, Database connection URLS, Secret keys, Server configs

- A .gitignore file tells Git which files it should not track. Prevents sensitive information from accidentally being uploaded to GitHub.

- Task is to locate files and understand which evnironment variables the project requires, and verify that secrets are protected.



## Project Overview
 - Understanding Tech Stack
    - Python -> Core Programming Language
    - Scapy -> Captures and analyzes network packets
    - Npcap -> Enables low-level network packet capture on Windows
    - Isolation Forest -> Detects unusual network activity using unsupervised machine learning
    - Flask -> Handles API requests and serves the web application
    - Vanilla JS -> Handles frontend behaviour and API requests
    - Chart.js -> Visualizes network statistics
    - CSS Grid -> Organizes the dashboard layout.

- Overall: 
    Starting layer is Network Traffic which contains incoming and outgoing packets

    Second layer is Scapy and Npcap, which captures and processes packets

    Then, Python and Isolation Forest analyze traffic and detect anomalies

    Flask backend then exposes information through API's

    Finally JS and Chart.js display information on the dashboard,


## Setup Commands

- check python version
    - python --version
- create virtual environment
    - python -m venv .venv
- activate virtual environment
    - .\.venv\Scripts\Activate.ps1
- install dependencies
    - pip install -r requirements.txt

- Virtual environments isolate software dependencies. 
    - Allow each project to have it's own set of dependencies
    - Prevents dependency conflicts
    - Makes projects easier to reproduce on other computers.
    - Keeps global python environment clean
    - Allows to test different package versions independently.



- pip install -r requirements.txt
    - installs SOC dependencies
    - pip is python's package manager
    - install - actually installs packages
    - -r -> reads package requirements from a file
    - requirements.txt - is the file that contains said required dependencies.
- python app.py
    - runs application


## Errors and Fixes

## Environment Variables

## API Endpoints

## Traced Request

## create_app() and socketio.run()
 - app = create_app()
 - socketio.run(app, host="0.0.0.0", port=5000, debug=True)
 - create_app constructs and configures the application by using api routes, databases and the config settings
 - app is now the configured flask application object
 - socketio.run(app,...) then starts the server and listens for requests on localhost:5000

 ## Why separate routes.py and app.py?
  - Idea called separation of concerns

  - Better organization by categorizing
  - For ex:
    - app.py for startup
    - routs.py for api handling
    - detector.py for ML detection
    - sniffer.py for packer capture
    - logger.py for logging
    - Allows for smaller modules with distinct responsibilities.
 - Makes code easier to read, debug, test, maintain, and extend.
 - Also allows for multiple developers to work on different parts of a project simultaneously.
 - Related to Single Responsibility Principle (SRP)


 ## Key Concepts
  - Dependency -> External Library my application/project relies on
  - Virtual Environment -> An isolated Python dependency environment
  - Entry point -> where program execution begins
  - Application factory -> a function that constructs an application
  - Server -> a running program that listens for and handles requests
  - Modularity -> organizing software into independent components