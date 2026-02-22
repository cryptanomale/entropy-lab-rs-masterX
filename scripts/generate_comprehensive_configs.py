#!/usr/bin/env python3
"""
Generate comprehensive browser configuration database for Randstorm scanner.

Extends the existing 100 configs with:
- 10 new languages × 4 Chrome versions × 2 resolutions = 80 configs
- 3 Linux distros × 4 Chrome versions × 3 resolutions = 36 configs
- 2 mobile platforms × 3 Chrome versions × 3 resolutions = 18 configs
- Chrome 46-48 × 2 resolutions = 6 configs
- Timezone variations = 6 configs

Total: 100 (existing) + 146 (new) = 246 configs
"""

import csv
import sys
from pathlib import Path

def load_existing_configs(csv_path):
    """Load existing 100 configs from phase1_top100.csv"""
    configs = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            configs.append(row)
    print(f"✓ Loaded {len(configs)} existing configs")
    return configs

def generate_language_variants():
    """Generate 80 configs for language diversity"""
    languages = [
        ('zh-CN', 'Chinese', 480),    # UTC+8
        ('ja-JP', 'Japanese', 540),    # UTC+9
        ('de-DE', 'German', -60),      # UTC+1
        ('fr-FR', 'French', -60),      # UTC+1
        ('es-ES', 'Spanish', -60),     # UTC+1
        ('pt-BR', 'Portuguese', 180),  # UTC-3
        ('ru-RU', 'Russian', -180),    # UTC+3
        ('ko-KR', 'Korean', 540),      # UTC+9
        ('it-IT', 'Italian', -60),     # UTC+1
        ('pl-PL', 'Polish', -60),      # UTC+1
    ]
    
    chrome_versions = ['25.0', '28.0', '30.0', '35.0']
    resolutions = [(1366, 768), (1920, 1080)]
    
    configs = []
    priority = 101
    
    for lang_code, lang_name, tz_offset in languages:
        for chrome_ver in chrome_versions:
            for width, height in resolutions:
                configs.append({
                    'priority': priority,
                    'user_agent': f'Mozilla/5.0 (Windows NT 6.1) Chrome/{chrome_ver}',
                    'screen_width': width,
                    'screen_height': height,
                    'color_depth': 24,
                    'timezone_offset': tz_offset,
                    'language': lang_code,
                    'platform': 'Win32',
                    'market_share_estimate': 0.001,  # Lower weight
                    'year_min': 2011,
                    'year_max': 2015,
                })
                priority += 1
    
    print(f"✓ Generated {len(configs)} language variant configs")
    return configs

def generate_linux_variants():
    """Generate 36 configs for Linux platforms"""
    linux_platforms = [
        'Linux x86_64',
        'Linux i686',
        'Linux armv7l',
    ]
    
    chrome_versions = ['25.0', '28.0', '30.0', '35.0']
    resolutions = [(1920, 1080), (1366, 768), (1600, 900)]
    
    configs = []
    priority = 181  # After languages
    
    for platform in linux_platforms:
        for chrome_ver in chrome_versions:
            for width, height in resolutions:
                configs.append({
                    'priority': priority,
                    'user_agent': f'Mozilla/5.0 (X11; Linux) Chrome/{chrome_ver}',
                    'screen_width': width,
                    'screen_height': height,
                    'color_depth': 24,
                    'timezone_offset': -300,  # US Eastern
                    'language': 'en-US',
                    'platform': platform,
                    'market_share_estimate': 0.0005,
                    'year_min': 2011,
                    'year_max': 2015,
                })
                priority += 1
    
    print(f"✓ Generated {len(configs)} Linux variant configs")
    return configs

def generate_mobile_variants():
    """Generate 18 configs for mobile platforms"""
    mobile_configs = [
        ('iPhone', 'iOS', [(320, 568), (375, 667), (414, 736)]),
        ('Android', 'Linux armv7l', [(360, 640), (412, 732), (384, 640)]),
    ]
    
    chrome_versions = ['28.0', '30.0', '35.0']
    
    configs = []
    priority = 217  # After Linux
    
    for device, platform, resolutions in mobile_configs:
        for chrome_ver in chrome_versions:
            for width, height in resolutions:
                configs.append({
                    'priority': priority,
                    'user_agent': f'Mozilla/5.0 ({device}) Chrome/{chrome_ver} Mobile',
                    'screen_width': width,
                    'screen_height': height,
                    'color_depth': 24,
                    'timezone_offset': -300,
                    'language': 'en-US',
                    'platform': platform,
                    'market_share_estimate': 0.0003,
                    'year_min': 2013,
                    'year_max': 2015,
                })
                priority += 1
    
    print(f"✓ Generated {len(configs)} mobile variant configs")
    return configs

def generate_late_chrome_variants():
    """Generate 6 configs for Chrome 46-48 (late 2015)"""
    chrome_versions = ['46.0', '47.0', '48.0']
    resolutions = [(1920, 1080), (1366, 768)]
    
    configs = []
    priority = 235  # After mobile
    
    for chrome_ver in chrome_versions:
        for width, height in resolutions:
            configs.append({
                'priority': priority,
                'user_agent': f'Mozilla/5.0 (Windows NT 10.0) Chrome/{chrome_ver}',
                'screen_width': width,
                'screen_height': height,
                'color_depth': 24,
                'timezone_offset': -300,
                'language': 'en-US',
                'platform': 'Win32',
                'market_share_estimate': 0.002,
                'year_min': 2015,
                'year_max': 2015,
            })
            priority += 1
    
    print(f"✓ Generated {len(configs)} late Chrome variant configs")
    return configs

def generate_timezone_variants():
    """Generate 6 configs for diverse timezones"""
    timezones = [
        (-480, 'PST'),   # US Pacific
        (0, 'GMT'),      # Greenwich
        (330, 'IST'),    # India
        (-240, 'EDT'),   # US Eastern
        (600, 'AEST'),   # Australia
        (-360, 'CST'),   # US Central
    ]
    
    configs = []
    priority = 241  # After late Chrome
    
    for tz_offset, tz_name in timezones:
        configs.append({
            'priority': priority,
            'user_agent': 'Mozilla/5.0 (Windows NT 6.1) Chrome/30.0',
            'screen_width': 1920,
            'screen_height': 1080,
            'color_depth': 24,
            'timezone_offset': tz_offset,
            'language': 'en-US',
            'platform': 'Win32',
            'market_share_estimate': 0.001,
            'year_min': 2011,
            'year_max': 2015,
        })
        priority += 1
    
    print(f"✓ Generated {len(configs)} timezone variant configs")
    return configs

def write_comprehensive_csv(output_path, all_configs):
    """Write all configs to comprehensive CSV"""
    fieldnames = [
        'priority', 'user_agent', 'screen_width', 'screen_height',
        'color_depth', 'timezone_offset', 'language', 'platform',
        'market_share_estimate', 'year_min', 'year_max'
    ]
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_configs)
    
    print(f"✓ Wrote {len(all_configs)} configs to {output_path}")

def main():
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    
    input_csv = repo_root / 'src/scans/randstorm/fingerprints/data/phase1_top100.csv'
    output_csv = repo_root / 'src/scans/randstorm/fingerprints/data/comprehensive.csv'
    
    if not input_csv.exists():
        print(f"Error: {input_csv} not found", file=sys.stderr)
        sys.exit(1)
    
    print("Generating comprehensive browser configuration database...")
    print()
    
    # Load existing 100
    existing = load_existing_configs(input_csv)
    
    # Generate new variants
    languages = generate_language_variants()
    linux = generate_linux_variants()
    mobile = generate_mobile_variants()
    late_chrome = generate_late_chrome_variants()
    timezones = generate_timezone_variants()
    
    # Combine all
    all_configs = existing + languages + linux + mobile + late_chrome + timezones
    
    print()
    print(f"Total configs: {len(all_configs)}")
    print(f"  - Existing: {len(existing)}")
    print(f"  - Languages: {len(languages)}")
    print(f"  - Linux: {len(linux)}")
    print(f"  - Mobile: {len(mobile)}")
    print(f"  - Late Chrome: {len(late_chrome)}")
    print(f"  - Timezones: {len(timezones)}")
    print()
    
    # Write output
    write_comprehensive_csv(output_csv, all_configs)
    print()
    print("✅ Comprehensive config generation complete!")

if __name__ == '__main__':
    main()
