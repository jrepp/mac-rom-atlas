#!/usr/bin/env python3
import re
import json
from pathlib import Path

SERVER_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = SERVER_ROOT.parent
MARKDOWN_FILE = REPO_ROOT / "out/books/M68000PRM/chapters/full_document.md"
OUTPUT_FILE = SERVER_ROOT / "data/knowledge_base.json"

SECTION_BOUNDARIES = {
    "section_1_introduction": (434, 1491),
    "section_2_addressing": (1492, 2275),
    "section_3_instruction_set_summary": (2276, 3392),
    "section_4_integer_instructions": (3393, 12235),
    "section_5_floating_point": (12236, 18271),
    "section_6_supervisor": (18272, 21683),
    "section_7_cpu32": (21684, 22243),
    "section_8_instruction_format": (22244, 25337),
}

INSTRUCTION_HEADING = re.compile(r"^#{1,3}\s+\*\*([A-Z][A-Za-z0-9]*(?:\.[A-Za-z])?)\*\*\s*$", re.MULTILINE)
FIELD_RE = re.compile(
    r"\*\*(Operation|Assembler(?:\s+Syntax)?|Syntax|Attributes|Description|Condition Codes|Instruction Format|Instruction Fields):?\*\*"
    r"|\b(Condition Codes|Instruction Format|Instruction Fields):",
    re.IGNORECASE,
)
NON_INSTRUCTION_HEADINGS = {"NOTE", "NOTES"}


def clean_text(text):
    kept_lines = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "picture" in line.lower() and "omitted" in line.lower():
            continue
        if line == "MOTOROLA" or "M68000 FAMILY PROGRAMMER" in line:
            continue
        if re.fullmatch(r"\*\*.*Instructions\*\*", line):
            continue
        if re.fullmatch(r"\*\*[A-Za-z0-9]+(?:\.[A-Za-z])?\*\*", line):
            continue
        if re.fullmatch(r"\*\*.*\([^)]+\)\*\*", line):
            continue
        if re.fullmatch(r"\d+-\d+", line):
            continue
        if re.fullmatch(r"\|[-|]+\|", line):
            continue
        if line.startswith("|**iption:**"):
            continue
        kept_lines.append(line)

    return re.sub(r"\s+", " ", " ".join(kept_lines).replace("<br>", " ")).strip()


def normalize_field_label(label):
    label = label.lower().replace(" ", "_")
    if label in {"assembler", "syntax", "assembler_syntax"}:
        return "syntax"
    if label == "condition_codes":
        return "condition_codes"
    return label


def extract_fields(content):
    content = re.sub(r"^#{1,3}\s+", "", content, flags=re.MULTILINE)
    fields = {}
    matches = list(FIELD_RE.finditer(content))
    for idx, match in enumerate(matches):
        key = normalize_field_label(match.group(1) or match.group(2))
        if key in {"instruction_format", "instruction_fields"}:
            continue
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(content)
        value = clean_text(content[start:end])
        if value:
            fields[key] = f"{fields[key]}; {value}" if key in fields else value
    return fields


def parse_instruction_block(lines, start_idx):
    instruction = {"name": "", "syntax": "", "operation": "", "description": "", 
                  "attributes": "", "condition_codes": "", "examples": [],
                  "section_refs": [], "line_number": start_idx}
    
    content = "\n".join(lines)
    
    name_match = INSTRUCTION_HEADING.search(content)
    if name_match:
        instruction["name"] = name_match.group(1)

    fields = extract_fields(content)
    instruction["syntax"] = fields.get("syntax", "")[:500]
    instruction["operation"] = fields.get("operation", "")[:500]
    instruction["description"] = fields.get("description", "")[:800]
    instruction["attributes"] = fields.get("attributes", "")[:300]
    instruction["condition_codes"] = fields.get("condition_codes", "")[:500]
     
    return instruction


def section_for_line(line_number):
    for section, (start, end) in SECTION_BOUNDARIES.items():
        if start <= line_number <= end:
            return section
    return None

def extract_knowledge_base():
    if not MARKDOWN_FILE.exists():
        raise FileNotFoundError(f"Source markdown not found: {MARKDOWN_FILE}")

    content = Path(MARKDOWN_FILE).read_text()
    lines = content.split('\n')
    
    instructions = []
    concepts = []
    
    in_instruction_section = False
    current_instruction_lines = []
    current_instruction_name = None
    instruction_start = 0
    
    section_pattern = re.compile(r'^## \*\*SECTION \d+')
    
    for i, line in enumerate(lines, start=1):
        if any(section_title in line for section_title in [
            "SECTION 4 INTEGER INSTRUCTIONS",
            "SECTION 5 FLOATING",
            "SECTION 6 SUPERVISOR",
            "SECTION 7 CPU32",
        ]):
            in_instruction_section = True
            continue
         
        if in_instruction_section:
            m = INSTRUCTION_HEADING.match(line.strip())
            if m and m.group(1).upper() not in NON_INSTRUCTION_HEADINGS:
                name = m.group(1)
                if current_instruction_name and name.lower() != current_instruction_name.lower():
                    instr = parse_instruction_block(current_instruction_lines, instruction_start)
                    if instr["name"]:
                        instructions.append(instr)
                    current_instruction_lines = []

                if not current_instruction_name or name.lower() != current_instruction_name.lower():
                    instruction_start = i
                current_instruction_name = name
             
            if section_pattern.match(line.strip()):
                in_instruction_section = False
                continue

            if current_instruction_name:
                current_instruction_lines.append(line)
         
        if any(kw in line.lower() for kw in ['programming model', 'user programming', 'supervisor programming', 
                                               'data register', 'address register', 'condition code']):
            concept = {"line": i, "text": line.strip()[:200], "type": "concept"}
            section = section_for_line(i)
            if section:
                concept["section"] = section
            concepts.append(concept)
    
    if current_instruction_name and current_instruction_lines:
        instr = parse_instruction_block(current_instruction_lines, instruction_start)
        if instr["name"]:
            instructions.append(instr)
    
    for i, line in enumerate(lines, start=1):
        if "INTRODUCTION" in line and "SECTION" in line:
            concepts.append({"line": i, "text": line.strip(), "type": "section_header", "section": "section_1_introduction"})
        if "ADDRESSING" in line and "SECTION" in line:
            concepts.append({"line": i, "text": line.strip(), "type": "section_header", "section": "section_2_addressing"})
        if "INSTRUCTION SET SUMMARY" in line:
            concepts.append({"line": i, "text": line.strip(), "type": "section_header", "section": "section_3_instruction_set_summary"})
        if "INTEGER INSTRUCTIONS" in line:
            concepts.append({"line": i, "text": line.strip(), "type": "section_header", "section": "section_4_integer_instructions"})
        if "FLOATING POINT" in line:
            concepts.append({"line": i, "text": line.strip(), "type": "section_header", "section": "section_5_floating_point"})
        if "SUPERVISOR" in line:
            concepts.append({"line": i, "text": line.strip(), "type": "section_header", "section": "section_6_supervisor"})
        if "CPU32" in line and "INSTRUCTIONS" in line:
            concepts.append({"line": i, "text": line.strip(), "type": "section_header", "section": "section_7_cpu32"})
        if "INSTRUCTION FORMAT" in line and "SUMMARY" in line:
            concepts.append({"line": i, "text": line.strip(), "type": "section_header", "section": "section_8_instruction_format"})
    
    knowledge_base = {
        "metadata": {
            "source": "Motorola M68000 Family Programmer's Reference Manual",
            "total_instructions": len(instructions),
            "total_concepts": len(concepts),
            "sections": list(SECTION_BOUNDARIES.keys())
        },
        "instructions": instructions,
        "concepts": concepts,
        "section_boundaries": SECTION_BOUNDARIES
    }
    
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(knowledge_base, indent=2))
    print(f"Knowledge base written to {OUTPUT_FILE}")
    print(f"  - {len(instructions)} instructions")
    print(f"  - {len(concepts)} concepts")
    
    return knowledge_base

if __name__ == "__main__":
    extract_knowledge_base()
