"""
Simple script to bump changelog version for release.
"""
import os
import sys
import argparse
from pathlib import Path


def get_parser():
    parser = argparse.ArgumentParser(
        prog="changelogger", description="Prepare changelog for release."
    )
    parser.add_argument("changelog_path")
    parser.add_argument("new_version_label")
    parser.add_argument("--unreleased_line", default="Unreleased")
    parser.add_argument("--section_line_char", default="+")
    return parser


def has_changes(lines, unreleased_index, section_line_char):
    found_content = False
    for line in lines[unreleased_index + 2 :]:
        if line and line.startswith(get_section_line(line, section_line_char)):
            break
        elif line:
            found_content = True
            break
    return found_content


def already_has_new_version(lines, new_version_label, section_line_char):
    exists = False
    if new_version_label in lines:
        new_version_idx = lines.index(new_version_label)
        next_line = lines[new_version_idx + 1]
        if next_line and next_line.startswith(
            get_section_line(next_line, section_line_char)
        ):
            exists = True
    return exists


def get_section_line(section_heading, section_line_char):
    return len(section_heading) * section_line_char


def main():
    parser = get_parser()
    args = parser.parse_args(sys.argv[1:])

    changelog_path = Path(args.changelog_path)
    if not changelog_path.exists():
        raise AssertionError(f"Changelog path {changelog_path} does not exist")

    with open(changelog_path, "r") as f:
        lines = [line.rstrip() for line in f.readlines()]
    idx = lines.index(args.unreleased_line)

    if not has_changes(lines, idx, args.section_line_char):
        raise AssertionError("No content was found in changelog.")

    if already_has_new_version(lines, args.new_version_label, args.section_line_char):
        raise AssertionError("Version already exists in changelog.")

    lines[idx] = args.new_version_label
    lines.insert(idx, os.linesep)
    lines.insert(idx, get_section_line(args.unreleased_line, args.section_line_char))
    lines.insert(idx, args.unreleased_line)

    # Make sure linebreak is at end of file.
    if lines[-1]:
        lines.append("")

    new_content = os.linesep.join(lines)
    with open(changelog_path, "w") as f:
        f.write(new_content)


if __name__ == "__main__":
    main()
