clean:
  rm -Rf build dist

build:
  # builds the macos app
  pyinstaller printGUI.py --onefile --windowed --name "TheProofmaker" --add-data="fingerprint.png:."
