#!/usr/bin/env python3

import json
import requests
import argparse
import sys
import html
from typing import Dict, List, Any, Optional
from datetime import datetime
from colorama import Fore, Back, Style, init

init(autoreset=True)

class Colors:
    SUCCESS = Fore.GREEN
    ERROR = Fore.RED
    WARNING = Fore.YELLOW
    INFO = Fore.CYAN
    HEADER = Fore.MAGENTA
    TECHNIQUE = Fore.BLUE
    TACTIC = Fore.LIGHTGREEN_EX
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

class MitreAttackGroupMapper:
    def __init__(self):
        self.enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.attack_data = None
        self.groups = {}
        self.techniques = {}
        self.tactics = {}
        self.relationships = []
        
    def print_banner(self):
        print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*80}")
        print(f"MITRE ATT&CK APT Group Mapping Tool - Navigator Compatible")
        print(f"{'='*80}{Colors.RESET}")
        print(f"{Colors.INFO}Purpose: Map APT groups to MITRE ATT&CK techniques")
        print(f"Output: Navigator-compatible JSON layer files")
        print(f"Compatible with: MITRE ATT&CK Navigator")
        print(f"{'='*80}{Colors.RESET}\n")
        
    def print_usage_guide(self):
        print(f"{Colors.HEADER}{Colors.BOLD}USAGE GUIDE{Colors.RESET}")
        print(f"{Colors.INFO}Available Commands:")
        print(f"  • {Colors.BOLD}Interactive Mode:{Colors.RESET} python apt_mapper.py")
        print(f"  • {Colors.BOLD}Direct Analysis:{Colors.RESET} python apt_mapper.py 'APT1'")
        print(f"  • {Colors.BOLD}List Groups:{Colors.RESET} python apt_mapper.py --list-groups")
        print(f"  • {Colors.BOLD}Generate Layer:{Colors.RESET} python apt_mapper.py 'G0006' -o custom.json")
        print(f"\n{Colors.WARNING}Examples of valid group inputs:")
        print(f"  • MITRE IDs: G0001, G0006, G0016")
        print(f"  • Group Names: APT1, Lazarus Group, Cozy Bear")
        print(f"  • Aliases: Comment Crew, HIDDEN COBRA, APT29")
        print(f"{'-'*60}\n")
        
    def clean_text(self, text: str) -> str:
        if not text:
            return ""
        
        text = html.unescape(text)
        text = text.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ')
        text = ' '.join(text.split())
        
        return text
        
    def load_attack_data(self):
        try:
            print(f"{Colors.INFO}Loading MITRE ATT&CK data from GitHub...")
            response = requests.get(self.enterprise_url, timeout=30)
            response.raise_for_status()
            self.attack_data = response.json()
            self._parse_attack_data()
            print(f"{Colors.SUCCESS}MITRE ATT&CK data loaded successfully!")
            print(f"{Colors.INFO}Loaded: {len(self.groups)} groups, {len(self.techniques)} techniques, {len(self.tactics)} tactics")
        except requests.RequestException as e:
            print(f"{Colors.ERROR}Error loading MITRE ATT&CK data: {e}")
            sys.exit(1)
    
    def _parse_attack_data(self):
        if not self.attack_data:
            return
            
        print(f"{Colors.INFO}Parsing MITRE ATT&CK data structures...")
        
        for obj in self.attack_data.get('objects', []):
            obj_type = obj.get('type')
            
            if obj_type == 'intrusion-set':
                group_id = obj.get('id')
                self.groups[group_id] = {
                    'id': group_id,
                    'attack_id': self._get_external_id(obj),
                    'name': self.clean_text(obj.get('name', '')),
                    'aliases': [self.clean_text(alias) for alias in obj.get('aliases', [])],
                    'description': self.clean_text(obj.get('description', '')),
                    'created': obj.get('created', ''),
                    'modified': obj.get('modified', ''),
                    'techniques': [],
                    'tactics': set(),
                    'platforms': set(),
                    'data_sources': set()
                }
            
            elif obj_type == 'attack-pattern':
                technique_id = obj.get('id')
                self.techniques[technique_id] = {
                    'id': technique_id,
                    'attack_id': self._get_external_id(obj),
                    'name': self.clean_text(obj.get('name', '')),
                    'description': self.clean_text(obj.get('description', '')),
                    'tactics': [phase.get('phase_name') for phase in obj.get('kill_chain_phases', [])],
                    'platforms': obj.get('x_mitre_platforms', []),
                    'data_sources': obj.get('x_mitre_data_sources', []),
                    'detection': self.clean_text(obj.get('x_mitre_detection', '')),
                    'is_subtechnique': obj.get('x_mitre_is_subtechnique', False)
                }
            
            elif obj_type == 'x-mitre-tactic':
                tactic_id = obj.get('id')
                self.tactics[tactic_id] = {
                    'id': tactic_id,
                    'attack_id': self._get_external_id(obj),
                    'name': self.clean_text(obj.get('name', '')),
                    'short_name': obj.get('x_mitre_shortname', ''),
                    'description': self.clean_text(obj.get('description', ''))
                }
            
            elif obj_type == 'relationship':
                self.relationships.append({
                    'source_ref': obj.get('source_ref'),
                    'target_ref': obj.get('target_ref'),
                    'relationship_type': obj.get('relationship_type'),
                    'description': self.clean_text(obj.get('description', '')),
                    'created': obj.get('created', '')
                })
    
    def _get_external_id(self, obj: Dict) -> str:
        external_refs = obj.get('external_references', [])
        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id', '')
        return ''
    
    def get_user_input(self):
        self.print_banner()
        self.print_usage_guide()
        
        print(f"{Colors.HEADER}{Colors.BOLD}INTERACTIVE GROUP SELECTION{Colors.RESET}")
        print(f"{Colors.INFO}Enter an APT group name, MITRE ID, or alias to analyze:")
        print(f"{Colors.WARNING}Tip: Use --list-groups to see all available groups")
        print(f"{'-'*60}")
        
        while True:
            group_input = input(f"{Colors.BOLD}Enter APT group name or ID: {Colors.RESET}").strip()
            if group_input:
                return group_input
            print(f"{Colors.ERROR}Please enter a valid APT group name or ID.")
    
    def find_group(self, group_input: str) -> Optional[Dict]:
        print(f"{Colors.INFO}Searching for group: {Colors.BOLD}{group_input}{Colors.RESET}")
        
        group_input_lower = group_input.lower().strip()
        
        for group_id, group_data in self.groups.items():
            if group_data['attack_id'].lower() == group_input_lower:
                print(f"{Colors.SUCCESS}Found by MITRE ID: {group_data['attack_id']}")
                return group_data
            
            if group_data['name'].lower() == group_input_lower:
                print(f"{Colors.SUCCESS}Found by name: {group_data['name']}")
                return group_data
            
            for alias in group_data['aliases']:
                if alias.lower() == group_input_lower:
                    print(f"{Colors.SUCCESS}Found by alias: {alias}")
                    return group_data
        
        print(f"{Colors.ERROR}Group not found in MITRE ATT&CK database")
        return None
    
    def map_group_techniques(self, group_data: Dict) -> Dict:
        print(f"{Colors.INFO}Mapping techniques for {Colors.BOLD}{group_data['name']}{Colors.RESET}...")
        
        group_id = group_data['id']
        technique_count = 0
        
        for relationship in self.relationships:
            if (relationship['source_ref'] == group_id and 
                relationship['relationship_type'] == 'uses' and
                relationship['target_ref'] in self.techniques):
                
                technique_data = self.techniques[relationship['target_ref']]
                technique_count += 1
                
                technique_entry = {
                    'attack_id': technique_data['attack_id'],
                    'name': technique_data['name'],
                    'description': technique_data['description'],
                    'tactics': technique_data['tactics'],
                    'platforms': technique_data['platforms'],
                    'data_sources': technique_data['data_sources'],
                    'detection': technique_data['detection'],
                    'is_subtechnique': technique_data['is_subtechnique'],
                    'relationship_description': relationship['description'],
                    'relationship_created': relationship['created']
                }
                
                group_data['techniques'].append(technique_entry)
                group_data['tactics'].update(technique_data['tactics'])
                group_data['platforms'].update(technique_data['platforms'])
                group_data['data_sources'].update(technique_data['data_sources'])
        
        print(f"{Colors.SUCCESS}Mapped {Colors.BOLD}{technique_count}{Colors.RESET} techniques")
        
        group_data['tactics'] = sorted(list(group_data['tactics']))
        group_data['platforms'] = sorted(list(group_data['platforms']))
        group_data['data_sources'] = sorted(list(group_data['data_sources']))
        
        return group_data
    
    def generate_navigator_layer(self, group_input: str) -> Dict:
        if not self.attack_data:
            self.load_attack_data()
        
        group_data = self.find_group(group_input)
        if not group_data:
            return self._generate_error_response(group_input)
        
        mapped_group = self.map_group_techniques(group_data.copy())
        
        print(f"{Colors.INFO}Generating Navigator-compatible layer...")
        
        description = mapped_group['description']
        if len(description) > 200:
            description = description[:200] + "..."
        
        layer = {
            "name": f"{mapped_group['name']} ({mapped_group['attack_id']}) - Techniques",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "enterprise-attack",
            "description": f"Techniques used by {mapped_group['name']} ({mapped_group['attack_id']}) based on MITRE ATT&CK data. {description}",
            "filters": {
                "platforms": mapped_group['platforms'] if mapped_group['platforms'] else ["Windows", "Linux", "macOS"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False,
                "expandedSubtechniques": "annotated"
            },
            "hideDisabled": False,
            "techniques": [],
            "gradient": {
                "colors": ["#ff6666", "#ffe766", "#8ec843"],
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [
                {
                    "label": f"Used by {mapped_group['name']}",
                    "color": "#fd8d3c"
                }
            ],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
            "metadata": [
                {
                    "name": "Group",
                    "value": f"{mapped_group['name']} ({mapped_group['attack_id']})"
                },
                {
                    "name": "Aliases",
                    "value": ", ".join(mapped_group['aliases']) if mapped_group['aliases'] else "None"
                },
                {
                    "name": "Total Techniques",
                    "value": str(len(mapped_group['techniques']))
                },
                {
                    "name": "Generated",
                    "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                {
                    "name": "Data Source",
                    "value": "MITRE ATT&CK Enterprise"
                }
            ],
            "links": [
                {
                    "label": "MITRE ATT&CK Group Page",
                    "url": f"https://attack.mitre.org/groups/{mapped_group['attack_id']}/"
                }
            ]
        }
        
        for technique in mapped_group['techniques']:
            primary_tactic = technique['tactics'][0] if technique['tactics'] else "execution"
            
            comment = technique['relationship_description']
            if len(comment) > 200:
                comment = comment[:200] + "..."
            
            technique_entry = {
                "techniqueID": technique['attack_id'],
                "tactic": primary_tactic,
                "score": 100,
                "color": "#fd8d3c",
                "comment": f"Used by {mapped_group['name']}. {comment}",
                "enabled": True,
                "metadata": [
                    {
                        "name": "Technique",
                        "value": technique['name']
                    },
                    {
                        "name": "Tactics",
                        "value": ", ".join(technique['tactics']) if technique['tactics'] else "Not specified"
                    },
                    {
                        "name": "Platforms",
                        "value": ", ".join(technique['platforms']) if technique['platforms'] else "Not specified"
                    },
                    {
                        "name": "Sub-technique",
                        "value": "Yes" if technique['is_subtechnique'] else "No"
                    }
                ],
                "links": [
                    {
                        "label": "MITRE ATT&CK Technique Page",
                        "url": f"https://attack.mitre.org/techniques/{technique['attack_id'].replace('.', '/')}/"
                    }
                ]
            }
            
            if not technique['is_subtechnique']:
                technique_entry["showSubtechniques"] = True
            
            layer["techniques"].append(technique_entry)
        
        return layer
    
    def _generate_error_response(self, group_input: str) -> Dict:
        suggestions = self.suggest_similar_groups(group_input)
        
        return {
            'error': f'APT group "{group_input}" not found in MITRE ATT&CK data',
            'suggestions': suggestions,
            'available_groups_sample': [
                f"{g['attack_id']} - {g['name']}" 
                for g in sorted(self.groups.values(), key=lambda x: x['attack_id'])[:10]
            ]
        }
    
    def display_group_analysis(self, mapped_group: Dict):
        print(f"\n{Colors.HEADER}{Colors.BOLD}GROUP ANALYSIS RESULTS{Colors.RESET}")
        print(f"{'='*60}")
        
        print(f"{Colors.HEADER}Group Profile:{Colors.RESET}")
        print(f"  • {Colors.BOLD}Name:{Colors.RESET} {mapped_group['name']}")
        print(f"  • {Colors.BOLD}MITRE ID:{Colors.RESET} {Colors.TECHNIQUE}{mapped_group['attack_id']}{Colors.RESET}")
        print(f"  • {Colors.BOLD}Aliases:{Colors.RESET} {', '.join(mapped_group['aliases']) if mapped_group['aliases'] else 'None'}")
        print(f"  • {Colors.BOLD}First Seen:{Colors.RESET} {mapped_group.get('created', 'Unknown')[:10] if mapped_group.get('created') else 'Unknown'}")
        print(f"  • {Colors.BOLD}Last Updated:{Colors.RESET} {mapped_group.get('modified', 'Unknown')[:10] if mapped_group.get('modified') else 'Unknown'}")
        
        print(f"\n{Colors.HEADER}Attack Statistics:{Colors.RESET}")
        print(f"  • {Colors.SUCCESS}Total Techniques:{Colors.RESET} {Colors.BOLD}{len(mapped_group['techniques'])}{Colors.RESET}")
        print(f"  • {Colors.TACTIC}Tactics Covered:{Colors.RESET} {Colors.BOLD}{len(mapped_group['tactics'])}{Colors.RESET}")
        print(f"  • {Colors.INFO}Platforms Targeted:{Colors.RESET} {Colors.BOLD}{len(mapped_group['platforms'])}{Colors.RESET}")
        print(f"  • {Colors.WARNING}Data Sources:{Colors.RESET} {Colors.BOLD}{len(mapped_group.get('data_sources', []))}{Colors.RESET}")
        
        print(f"\n{Colors.HEADER}Tactics Used:{Colors.RESET}")
        for tactic in mapped_group['tactics']:
            tactic_techniques = [t for t in mapped_group['techniques'] if 'tactics' in t and tactic in t['tactics']]
            print(f"  • {Colors.TACTIC}{tactic.title()}{Colors.RESET}: {len(tactic_techniques)} techniques")
        
        print(f"\n{Colors.HEADER}Target Platforms:{Colors.RESET}")
        for platform in mapped_group['platforms']:
            print(f"  • {Colors.INFO}{platform}{Colors.RESET}")
        
        print(f"{'='*60}")
    
    def save_navigator_layer(self, layer_data: Dict, filename: str):
        try:
            cleaned_layer = self._clean_layer_data(layer_data)
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(cleaned_layer, f, indent=2, ensure_ascii=False, separators=(',', ': '))
            
            print(f"{Colors.SUCCESS}Navigator layer saved to: {Colors.BOLD}{filename}{Colors.RESET}")
            print(f"{Colors.INFO}Import this file into MITRE ATT&CK Navigator")
            
            self._validate_json_file(filename)
            
        except IOError as e:
            print(f"{Colors.ERROR}Error saving file: {e}")
            sys.exit(1)
    
    def _clean_layer_data(self, data):
        if isinstance(data, dict):
            return {key: self._clean_layer_data(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self._clean_layer_data(item) for item in data]
        elif isinstance(data, str):
            return self.clean_text(data)
        else:
            return data
    
    def _validate_json_file(self, filename: str):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                json.load(f)
            print(f"{Colors.SUCCESS}JSON validation: File structure is valid")
        except json.JSONDecodeError as e:
            print(f"{Colors.ERROR}JSON validation failed: {e}")
            print(f"{Colors.WARNING}The file may still work but has formatting issues")
    
    def list_available_groups(self):
        if not self.attack_data:
            self.load_attack_data()
        
        print(f"\n{Colors.HEADER}{Colors.BOLD}Available APT Groups in MITRE ATT&CK ({len(self.groups)} total){Colors.RESET}")
        print(f"{'='*90}")
        print(f"{Colors.BOLD}{'ID':<10} {'Name':<35} {'Aliases'}{Colors.RESET}")
        print(f"{'-'*90}")
        
        for group in sorted(self.groups.values(), key=lambda x: x['attack_id']):
            aliases_str = ', '.join(group['aliases'][:3])
            if len(group['aliases']) > 3:
                aliases_str += f' (+{len(group["aliases"]) - 3} more)'
            
            print(f"{Colors.TECHNIQUE}{group['attack_id']:<10}{Colors.RESET} {Colors.BOLD}{group['name']:<35}{Colors.RESET} {Colors.INFO}{aliases_str}{Colors.RESET}")
    
    def suggest_similar_groups(self, group_input: str) -> List[str]:
        if not self.attack_data:
            self.load_attack_data()
        
        suggestions = []
        group_input_lower = group_input.lower()
        
        for group_data in self.groups.values():
            if group_input_lower in group_data['name'].lower():
                suggestions.append(f"{group_data['attack_id']} - {group_data['name']}")
            
            for alias in group_data['aliases']:
                if group_input_lower in alias.lower():
                    suggestions.append(f"{group_data['attack_id']} - {group_data['name']} (alias: {alias})")
                    break
        
        return suggestions[:5]

def main():
    parser = argparse.ArgumentParser(
        description='Map APT groups to MITRE ATT&CK tactics and techniques - Navigator Compatible',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.HEADER}Examples:{Colors.RESET}
  python apt_mapper.py                           
  python apt_mapper.py "APT1"                    
  python apt_mapper.py "G0006" -o custom.json   
  python apt_mapper.py --list-groups             
        """
    )
    
    parser.add_argument(
        'group',
        nargs='?',
        help='APT group name, ID, or alias (optional - will prompt if not provided)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output JSON file name (auto-generated if not specified)'
    )
    parser.add_argument(
        '--list-groups',
        action='store_true',
        help='List all available APT groups in MITRE ATT&CK'
    )
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Force interactive mode even if group is provided'
    )
    
    args = parser.parse_args()
    
    mapper = MitreAttackGroupMapper()
    
    if args.list_groups:
        mapper.list_available_groups()
        return
    
    if args.group and not args.interactive:
        group_input = args.group
        mapper.print_banner()
    else:
        group_input = mapper.get_user_input()
    
    print(f"\n{Colors.INFO}Analyzing APT group: {Colors.BOLD}{group_input}{Colors.RESET}")
    print(f"{'-'*60}")
    
    navigator_layer = mapper.generate_navigator_layer(group_input)
    
    if 'error' in navigator_layer:
        print(f"{Colors.ERROR}{navigator_layer['error']}")
        
        if navigator_layer.get('suggestions'):
            print(f"\n{Colors.WARNING}Did you mean one of these?")
            for suggestion in navigator_layer['suggestions']:
                print(f"  • {Colors.INFO}{suggestion}{Colors.RESET}")
        else:
            print(f"\n{Colors.INFO}Sample available groups:")
            for group in navigator_layer['available_groups_sample']:
                print(f"  • {Colors.TECHNIQUE}{group}{Colors.RESET}")
        return
    
    group_data = {
        'name': navigator_layer['metadata'][0]['value'].split(' (')[0],
        'attack_id': navigator_layer['metadata'][0]['value'].split('(')[1].split(')')[0],
        'aliases': navigator_layer['metadata'][1]['value'].split(', ') if navigator_layer['metadata'][1]['value'] != 'None' else [],
        'created': '',
        'modified': '',
        'techniques': [],
        'tactics': [],
        'platforms': navigator_layer['filters']['platforms'],
        'data_sources': []
    }
    
    all_tactics = set()
    for tech in navigator_layer['techniques']:
        tactics_metadata = next((m for m in tech.get('metadata', []) if m.get('name') == 'Tactics'), None)
        tactics_list = tactics_metadata['value'].split(', ') if tactics_metadata and tactics_metadata['value'] != 'Not specified' else []
        
        if not tactics_list and tech.get('tactic'):
            tactics_list = [tech['tactic']]
        
        technique_data = {
            'techniqueID': tech['techniqueID'],
            'name': next((m['value'] for m in tech.get('metadata', []) if m.get('name') == 'Technique'), tech['techniqueID']),
            'tactics': tactics_list,
            'platforms': tech.get('platforms', []),
            'comment': tech.get('comment', ''),
            'enabled': tech.get('enabled', True)
        }
        
        group_data['techniques'].append(technique_data)
        all_tactics.update(tactics_list)
    
    group_data['tactics'] = sorted(list(all_tactics))
    
    mapper.display_group_analysis(group_data)
    
    if args.output:
        output_file = args.output
    else:
        safe_name = group_input.replace(' ', '_').replace('/', '_').lower()
        safe_name = ''.join(c for c in safe_name if c.isalnum() or c in '_-')
        output_file = f"{safe_name}_navigator_layer.json"
    
    mapper.save_navigator_layer(navigator_layer, output_file)
    
    print(f"\n{Colors.SUCCESS}{Colors.BOLD}Analysis Complete!{Colors.RESET}")
    print(f"{Colors.INFO}Output file: {Colors.BOLD}{output_file}{Colors.RESET}")
    print(f"{Colors.INFO}Import into MITRE ATT&CK Navigator for visualization")
    print(f"{Colors.WARNING}Next steps: Open Navigator and use 'Open Existing Layer' to import")

if __name__ == '__main__':
    main()
