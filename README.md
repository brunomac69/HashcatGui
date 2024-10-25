
# Hashcat Command Generator

![Hashcat Command Generator Screenshot](screenshot_1.png.png)

This Python-based tool provides a graphical interface (GUI) to generate and execute **Hashcat** commands. It is designed to simplify the process of setting up and running Hashcat attacks by offering easy-to-use input fields, checkboxes, and buttons for customizing your commands.
Sorry some comments are in Portuguese. Upsss.

## Features

- **Hash Type Selection**: Easily select the hash type you want to use.
- **Attack Type Selection**: Choose from various attack modes, including dictionary attacks, combinator attacks, and mask attacks.
- **Input Files**: Specify hash files, wordlists, and masks with the option to add up to three wordlists.
- **Rules Support**: Apply Hashcat rules to modify your attack strategies.
- **Session Management**: Define or restore previous Hashcat sessions for more efficient workflows.
- **Additional Parameters**: Configure additional Hashcat parameters like output file, session, and other flags (e.g., `--force`, `--gpu-temp-disable`, `--stdout`).
- **Command Preview**: Preview the generated Hashcat command before execution.
- **New Terminal Window Option**: Option to execute commands in a new terminal window.
- **History**: Track and view previously executed commands.

## Prerequisites

- Python 3.x
- `tkinter` library for the GUI
- Hashcat installed on your system. Make sure Hashcat is accessible from the path defined in the tool or modify the hardcoded path if necessary.

### Install Dependencies

To install the required Python libraries:

```bash
pip install tkinter
```

## Usage

1. Clone the repository:

    ```bash
    git clone https://github.com/brunomac69/HashcatGui
    ```

2. Run the `hashcatgui.py` script:

    ```bash
    python hashcatgui.py
    ```

3. Fill out the fields in the GUI to generate your Hashcat command:
   - **Algorithm to use (-m)**: Select the hash algorithm (e.g., MD5, SHA1).
   - **Type of Attack (-a)**: Choose the type of attack (e.g., Wordlist, Mask, etc.).
   - **Hash or File**: Specify the path to your hash file.
   - **Wordlists**: Input one or more wordlists. If you use multiple wordlists, the tool will automatically set the attack mode to `-a1`.
   - **Rules (-r)**: Optionally, add rules to modify wordlist behavior.
   - **Other Parameters**: Add additional parameters or flags to customize the command.
   - **Session**: Specify or restore a previous session.
   - **Execution Options**: Optionally check flags like `--force`, `--stdout`, or `--keep-guessing`.

4. Click **Generate Hashcat Command** to see the command preview.
5. Click **Execute Command** to run the command directly in your terminal.
6. You can also track command history and view previously executed commands.

## Screenshots

Include screenshots here to demonstrate usage.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

1. Fork the repository.
2. Create your feature branch:

    ```bash
    git checkout -b feature/NewFeature
    ```

3. Commit your changes:

    ```bash
    git commit -m "Add new feature"
    ```

4. Push to the branch:

    ```bash
    git push origin feature/NewFeature
    ```

5. Open a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgments

- Thanks to the [Hashcat](https://hashcat.net/hashcat/) project for creating such a powerful tool for password recovery.
- Inspired by similar Hashcat GUI implementations.
