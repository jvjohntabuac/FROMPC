Elden Ring Applications

Part 1 - Clone Project

Cloning project repository from https://github.com/jvjohntabuac/Frompc.git

using the following command;

    git clone https://github.com/jvjohntabuac/Frompc.git


Part 2 - Installation Instructions

1. Go to the following site and read the installation instructions.
https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/

2. Launch Terminal window.

3. Go the Project location using the following command;

    cd /project/location/path

4. Under the project directory, run the following command

    python3 -m venv .venv

    Note: You should exclude your virtual environment directory from your version control system using .gitignore or similar.

5. Activate a virtual environment
Before you can start installing or using packages in your virtual environment you’ll need to activate it. Activating a virtual environment will put the virtual environment-specific python and pip executables into your shell’s PATH.

    Command:

    source .venv/bin/activate

    Note:  Ensure to acknowledge prompt to activate the virtual environment.

6. Run following command::

    # MacOS
    which python 

    # Windows
    where python

7. Install all packages by running the following command.

    pip install -r requirements.txt

    

