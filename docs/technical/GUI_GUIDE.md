# GUI User Guide

## Overview

Entropy Lab RS includes a modern graphical user interface (GUI) built with egui, providing an intuitive way to run vulnerability scanners without command-line knowledge.

## Features

### Main Window

The GUI provides the following sections:

1. **Scanner Selection**
   - Dropdown menu to select vulnerability scanner
   - Description of each scanner's purpose
   - GPU availability indicator for supported scanners

2. **Configuration Panel**
   - Scanner-specific options (limit, target address, timestamps, etc.)
   - Advanced settings for RPC configuration
   - GPU acceleration toggle

3. **Control Buttons**
   - Start Scan: Begin scanning with current configuration
   - Stop Scan: Stop currently running scan
   - Reset: Clear all configuration to defaults

4. **Status Display**
   - Real-time progress bar
   - Status messages
   - Scan results or error messages

## Getting Started

### Launch the GUI

```bash
# With GPU support
cargo run --release --features "gpu,gui" -- gui

# Without GPU support
cargo run --release --features gui -- gui
```

### Running a Scan

1. **Select a Scanner**: Choose from the dropdown menu
2. **Configure Options**: Enter required parameters (if any)
3. **Click Start Scan**: Begin the vulnerability scan
4. **Monitor Progress**: Watch the real-time progress bar
5. **View Results**: Check the status panel for results

## Scanner Descriptions

### Cake Wallet (2024)
Scans for the Cake Wallet 2024 vulnerability using Electrum seed format. Searches 2^20 (1,048,576) entropy space from weak PRNG.

**Configuration:**
- Scan Limit: Number of seeds to check (default: 1,048,576)

### Cake Wallet Targeted
Scans only the 8,757 confirmed vulnerable Cake Wallet seeds. This is much faster as it only checks known vulnerable patterns.

**Configuration:** None required

### Trust Wallet (2023)
Reproduces Trust Wallet MT19937 weakness (CVE-2023-31290).

**Configuration:**
- Target Address: (Optional) Specific address to search for

### Mobile Sensor Entropy
Tests mobile sensor-based entropy vulnerabilities from Android devices.

**Configuration:**
- Target Address: (Optional) Specific address to search for

### Milk Sad
Scans for the Milk Sad vulnerability (CVE-2023-39910). This scanner discovered 224k+ vulnerable wallets in 2018.

**Configuration:**
- Start Timestamp: Beginning of time range to scan
- End Timestamp: End of time range to scan
- Multi-path: Enable to check multiple derivation paths
- RPC Settings: (Advanced) Bitcoin RPC for balance checking

### Profanity
Scans for Profanity vanity address vulnerabilities (CVE-2022-40769).

**Configuration:**
- Target Address: (Optional) Specific address to search for

### Android SecureRandom
Detects duplicate R values in ECDSA signatures (2013 vulnerability).

**Configuration:**
- Start Block: Beginning block height to scan
- End Block: Ending block height to scan
- RPC Settings: (Advanced) Required for blockchain access

### Cake Wallet Dart PRNG
Reverse-engineers Cake Wallet seeds using time-based Dart PRNG (2020-2021).

**Configuration:** None required (scans 2020-2021 period)

## Advanced Features

### GPU Acceleration

- The GUI automatically detects GPU availability
- Green indicator: GPU available and ready
- Yellow indicator: GPU not available, using CPU
- Toggle GPU on/off for supported scanners

### RPC Configuration

For scanners that support balance checking (Milk Sad, Android SecureRandom):

1. Click "Show Advanced Options"
2. Enter RPC URL (default: http://127.0.0.1:8332)
3. Enter RPC Username
4. Enter RPC Password (shown as dots for security)

**Security Note:** Credentials are only stored in memory during the scan and are never saved to disk.

## Keyboard Shortcuts

Currently, the GUI uses standard mouse interaction. Keyboard shortcuts may be added in future versions.

## Performance Tips

1. **Use GPU Acceleration**: Enable GPU for 10-100x speedup on supported scanners
2. **Release Build**: Always use `--release` flag for better performance
3. **Targeted Scans**: Use targeted scanners when available (e.g., Cake Wallet Targeted)
4. **Reasonable Limits**: Start with smaller limits to test before running full scans

## Troubleshooting

### GUI Won't Start

**Problem:** Error about GUI feature not enabled
**Solution:** Compile with `--features gui` or `--features "gpu,gui"`

### GPU Not Available

**Problem:** Yellow indicator showing GPU not available
**Solution:** 
- Install OpenCL drivers for your GPU
- Compile with `--features gpu`
- Check that OpenCL libraries are installed (see README)

### Scan Fails Immediately

**Problem:** Scan stops with error message
**Solution:**
- Check error message in status panel
- Verify all required configuration fields are filled
- For RPC scanners, ensure Bitcoin node is running and accessible

### Slow Performance

**Problem:** Scan is taking too long
**Solution:**
- Enable GPU acceleration if available
- Use release build (`--release` flag)
- Consider using targeted scanners when available
- Reduce scan limits for testing

## Contributing

Found a bug or have a feature request for the GUI? Please open an issue on GitHub with:
- Description of the problem or feature
- Steps to reproduce (for bugs)
- Screenshots if applicable
- Your operating system and GPU information

## Security Considerations

- **Credentials**: RPC passwords are not logged or saved
- **Results**: Scan results are displayed but not automatically saved
- **Research Use**: This tool is for authorized security research only
- **Responsible Disclosure**: Follow responsible disclosure practices

## Future Enhancements

Planned features for future releases:
- [ ] Save/load configuration profiles
- [ ] Export scan results to file
- [ ] Keyboard shortcuts
- [ ] Dark/light theme toggle
- [ ] Multi-window support for parallel scans
- [ ] Result visualization graphs
- [ ] Scan history
