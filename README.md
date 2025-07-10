# MITRE ATT&CK APT Group Mapping Tool

## Description
The **MITRE ATT&CK APT Group Mapping Tool** is a Python-based utility designed to map Advanced Persistent Threat (APT) groups to their associated MITRE ATT&CK techniques and tactics. It fetches data from the MITRE ATT&CK Enterprise dataset and generates JSON layer files compatible with the MITRE ATT&CK Navigator. This tool allows cybersecurity professionals to analyze and visualize the techniques used by specific APT groups, aiding in threat intelligence, incident response, and security planning.

The tool supports both interactive and command-line modes, enabling users to query APT groups by their MITRE ID (e.g., G0006), name (e.g., APT1), or aliases (e.g., Comment Crew). It produces detailed analysis output and saves results in a format suitable for visualization in the MITRE ATT&CK Navigator.

## Features
- **Data Retrieval**: Automatically fetches the latest MITRE ATT&CK Enterprise dataset from GitHub.
- **Group Analysis**: Maps APT groups to their associated techniques, tactics, platforms, and data sources.
- **Navigator Compatibility**: Generates JSON layer files compatible with the MITRE ATT&CK Navigator for visualization.
- **Interactive Mode**: Allows users to interactively select APT groups for analysis.
- **Command-Line Support**: Supports direct analysis of specific groups and listing of all available groups.
- **Error Handling**: Provides suggestions for similar groups if the input is not found.
- **Colored Output**: Uses color-coded console output for better readability (via the `colorama` library).

## Requirements
- **Python**: Version 3.6 or higher
- **Dependencies**:
  - `requests` (for fetching MITRE ATT&CK data)
  - `colorama` (for colored console output)
  - `argparse` (included in Python standard library)
  - `json` (included in Python standard library)
  - `html` (included in Python standard library)
  - `typing` (included in Python standard library)
  - `datetime` (included in Python standard library)

Install the required dependencies using pip:
```bash
pip install requests colorama
```

## Installation
1. Clone or download this repository to your local machine:
   ```bash
   git clone https://github.com/mohabye/mitre-attack-apt-mapper.git
   ```
2. Navigate to the project directory:
   ```bash
   cd mitre-attack-apt-mapper
   ```
3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
   (Create a `requirements.txt` file with `requests` and `colorama` if not already present.)

## Usage
The tool can be used in several ways, depending on your needs. Below are the available commands and examples.

### Available Commands
- **Interactive Mode**: Run the script without arguments to enter interactive mode, where you can input an APT group name, ID, or alias.
  ```bash
  python apt_mapper.py
  ```
- **Direct Analysis**: Specify an APT group name, ID, or alias directly for analysis.
  ```bash
  python apt_mapper.py "APT1"
  ```
- **Generate Layer File**: Specify an output file for the Navigator-compatible JSON layer.
  ```bash
  python apt_mapper.py "G0006" -o apt1_layer.json
  ```
- **List All Groups**: Display all available APT groups in the MITRE ATT&CK dataset.
  ```bash
  python apt_mapper.py --list-groups
  ```
- **Force Interactive Mode**: Use the `--interactive` flag to force interactive mode even when a group is provided.
  ```bash
  python apt_mapper.py "APT1" --interactive
  ```

### Example Inputs
- **MITRE IDs**: `G0001`, `G0006`, `G0016`
- **Group Names**: `APT1`, `Lazarus Group`, `Cozy Bear`
- **Aliases**: `Comment Crew`, `HIDDEN COBRA`, `APT29`

### Output
- **Console Output**: Displays a detailed analysis of the APT group, including:
  - Group profile (name, MITRE ID, aliases, creation/modification dates)
  - Attack statistics (total techniques, tactics, platforms, and data sources)
  - List of tactics and targeted platforms
- **JSON Layer File**: A Navigator-compatible JSON file (e.g., `apt1_navigator_layer.json`) that can be imported into the MITRE ATT&CK Navigator for visualization.

### Importing into MITRE ATT&CK Navigator
1. Open the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. Click **Open Existing Layer** and select the generated JSON file (e.g., `apt1_navigator_layer.json`).
3. The Navigator will display the techniques and tactics associated with the APT group, color-coded for easy visualization.

## How It Works
1. **Data Loading**: The tool fetches the latest MITRE ATT&CK Enterprise dataset from the official GitHub repository (`enterprise-attack.json`).
2. **Data Parsing**: The script parses the JSON data to extract information about:
   - **Intrusion Sets** (APT groups)
   - **Attack Patterns** (techniques)
   - **Tactics**
   - **Relationships** (mappings between groups and techniques)
3. **Group Mapping**: For a given APT name, ID, or alias, the tool:
   - Identifies the group in the dataset.
   - Maps associated techniques and tactics using relationship data.
   - Collects additional metadata like platforms and data sources.
4. **Layer Generation**: Creates a JSON layer file compatible with the MITRE ATT&CK Navigator, including:
   - Technique IDs, names, and tactics
   - Metadata about the group and analysis
   - Links to MITRE ATT&CK pages for further reference
5. **Output Handling**:
   - Displays a detailed analysis in the console with color-coded formatting.
   - Saves the JSON layer to a file (user-specified or auto-generated name).
   - Validates the JSON file to ensure compatibility with the Navigator.

## Example Output
For the command `python apt_mapper.py "APT1"`:
- **Console Output**:
  ```
  MITRE ATT&CK APT Group Mapping Tool - Navigator Compatible
  ================================================================================
  Purpose: Map APT groups to MITRE ATT&CK techniques
  Output: Navigator-compatible JSON layer files
  Compatible with: MITRE ATT&CK Navigator
  ================================================================================

  Analyzing APT group: APT1
  ------------------------------------------------------------
  Loading MITRE ATT&CK data from GitHub...
  MITRE ATT&CK data loaded successfully!
  Loaded: 140 groups, 635 techniques, 14 tactics
  Searching for group: APT1
  Found by name: APT1
  Mapping techniques for APT1...
  Mapped 25 techniques
  Generating Navigator-compatible layer...

  GROUP ANALYSIS RESULTS
  ==================================================
  Group Profile:
    • Name: APT1
    • MITRE ID: G0006
    • Aliases: Comment Crew, Comment Group
    • First Seen: 2013-05-17
    • Last Updated: 2023-04-12

  Attack Statistics:
    • Total Techniques: 25
    • Tactics Covered: 8
    • Platforms Targeted: 3
    • Data Sources: 12

  Tactics Used:
    • Execution: 3 techniques
    • Persistence: 4 techniques
    • Privilege Escalation: 2 techniques
    ...

  Target Platforms:
    • Windows
    • Linux
    • macOS
  ==================================================

  Navigator layer saved to: apt1_navigator_layer.json
  Import this file into MITRE ATT&CK Navigator
  JSON validation: File structure is valid

  Analysis Complete!
  Output file: apt1_navigator_layer.json
  Import into MITRE ATT&CK Navigator for visualization
  Next steps: Open Navigator and use 'Open Existing Layer' to import
  ```
- **Generated File**: `apt1_navigator_layer.json` (Navigator-compatible JSON layer file)

## Limitations
- **Internet Dependency**: Requires an active internet connection to fetch the MITRE ATT&CK dataset.
- **Dataset Accuracy**: Relies on the accuracy and completeness of the MITRE ATT&CK Enterprise dataset.
- **Group Name Ambiguity**: Some group names or aliases may require exact matches or MITRE IDs for accurate results.
- **Navigator Dependency**: The generated JSON files are designed for use with the MITRE ATT&CK Navigator; manual parsing may be required for other purposes.

## Contributing
Contributions are welcome! Please submit issues or pull requests to the GitHub repository. When contributing:
- Ensure code follows PEP 8 style guidelines.
- Add tests for new features or bug fixes.
- Update this README if new features or usage instructions are added.
