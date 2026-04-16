import re
from typing import List, Dict

def parse_requirements(content: str) -> List[Dict]:
    dependencies = []
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # matches pkg==version or pkg>=version
        match = re.match(r'^([a-zA-Z0-9\-_]+)([=<>!~]+)([a-zA-Z0-9\._]+)', line)
        if match:
            dependencies.append({
                "package": match.group(1),
                "operator": match.group(2),
                "version": match.group(3)
            })
    return dependencies

def parse_package_json(content: str) -> List[Dict]:
    import json
    dependencies = []
    try:
        data = json.loads(content)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        all_deps = {**deps, **dev_deps}
        for pkg, ver in all_deps.items():
            version = re.sub(r'[\^~>=<]', '', ver)
            dependencies.append({
                "package": pkg,
                "version": version
            })
    except:
        pass
    return dependencies
