# (c) 2016, Allen Sanabria <asanabria@linuxdynasty.org>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
author: "Allen Sanabria (@linuxdynasty)"
module: include_vars_dir
version_added: "2.2"
short_description: Load variables files recursively from a directory.
description:
     - Loads variables from a YAML/JSON files dynamically from within a directory recursively during task runtime. The files are sorted alphabetically before being loaded.
options:
  dir:
    version_added: "2.2"
    description:
      - The directory name from which the variables should be loaded.
      - If the path is relative, it will look for the file in vars/ subdirectory of a role or relative to playbook.
  name:
    version_added: "2.2"
    description:
      - The name of a variable into which assign the included vars, if omitted (null) they will be made top level vars.
    default: null
  depth:
    version_added: "2.2"
    description:
      - By default, this module will recursively go through each sub directory and load up the variables. By explicitly setting the depth, this module will only go as deep as the depth.
    default: 0
  files_matching:
    version_added: "2.2"
    description:
      - Limit the variables that are loaded within any directory to this regular expression.
    default: null
  ignore_files:
    version_added: "2.2"
    description:
      - List of file names to ignore. The defaults can not be overridden, but can be extended.
    default:
      - ".*.md"
      - "*.py"
      - "*.pyc"
'''

EXAMPLES = """
# Include vars of stuff.yml into the 'stuff' variable (2.2).
- include_vars_dir:
    file: stuff.yml
    name: stuff
# Conditionally decide to load in variables into 'plans' when x is 0, otherwise do not. (2.2)
- include_vars_dir: file=contingency_plan.yml name=plans
  when: x == 0
# Load a variable file based on the OS type, or a default if not found.
- include_vars_dir: "{{ item }}"
  with_first_found:
   - "{{ ansible_distribution }}.yml"
   - "{{ ansible_os_family }}.yml"
   - "default.yml"
# bare include (free-form)
- include_vars_dir: myvars.yml
"""
