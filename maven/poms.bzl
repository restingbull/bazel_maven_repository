#
# Description:
#   Utilities for extracting information from pom files.
#
load(":utils.bzl", "strings")
load(":xml.bzl", "xml")

# An enum of known labels
labels = struct(
    # Structural tags
    PROJECT = "project",
    PARENT = "parent",
    DEPENDENCY_MANAGEMENT = "dependencyManagement",
    DEPENDENCIES = "dependencies",
    DEPENDENCY = "dependency",
    PROPERTIES = "properties",

    # Identifiers
    ARTIFACT_ID = "artifactId",
    GROUP_ID = "groupId",
    VERSION = "version",
    TYPE = "type",
    SCOPE = "scope",
    OPTIONAL = "optional",
    CLASSIFIER = "classifier",
    SYSTEM_PATH = "systemPath",
    PACKAGING = "packaging",  # The same as type, but in the main section.
)

def _process_dependency(dep_node):
    group_id = None
    artifact_id = None
    version = "INFERRED"
    type = "jar"
    optional = False
    scope = "compile"
    classifier = None
    system_path = None

    for c in dep_node.children:
        if c.label == labels.GROUP_ID:
            group_id = c.content
        elif c.label == labels.ARTIFACT_ID:
            artifact_id = c.content
        elif c.label == labels.VERSION:
            # TODO(cgruber) handle property substitution.
            version = "INFERRED" if strings.contains(c.content, "$") else c.content
        elif c.label == labels.CLASSIFIER:
            classifier = c.content
        elif c.label == labels.TYPE:
            type = c.content
        elif c.label == labels.SCOPE:
            scope = c.content
        elif c.label == labels.OPTIONAL:
            optional = bool(c.content)
        elif c.label == labels.SYSTEM_PATH:
            system_path = c.content

    return struct(
        group_id = group_id,
        artifact_id = artifact_id,
        version = version,
        type = type,
        optional = optional,
        scope = scope,
        classifier = classifier,
        system_path = system_path,
        coordinate = "%s:%s" % (group_id, artifact_id),
    )

# Extracts dependency coordinates from a given <dependencies> node of a pom node.
# The parameter should be an xml node containing the tag <dependencies>
def _extract_dependencies(parent_node):
    node = xml.find_first(parent_node, labels.DEPENDENCIES)
    return [_process_dependency(x) for x in node.children] if bool(node) else []

# Extracts dependency coordinates from a given <dependencies> node within a <dependencyManagement> node of a pom node.
# The parameter should be an xml node containing the tag <dependencyManagement>
def _extract_dependency_management(project_node):
    node = xml.find_first(project_node, labels.DEPENDENCY_MANAGEMENT)
    return poms.extract_dependencies(node) if bool(node) else []

def _process_parent(dep_node):
    group_id = None
    artifact_id = None
    version = None
    for c in dep_node.children:
        if c.label == labels.GROUP_ID:
            group_id = c.content
        elif c.label == labels.ARTIFACT_ID:
            artifact_id = c.content
        elif c.label == labels.VERSION:
            version = c.content
    return struct(
        group_id = group_id,
        artifact_id = artifact_id,
        version = version,
        packaging = "pom",  # Parent POMs must be pure metadata artifacts (only a .pom, no .jar/.aar, etc.)
        original_spec = "%s:%s:%s:pom" % (group_id, artifact_id, version),
        classifier = None,
    )

# Extracts parent specification for the supplied pom file.
# The parameter should be the project node of a parsed xml document tree, returned by poms.parse(xml_text)
def _extract_parent(project):
    for node in project.children:
        if node.label == labels.PARENT:
            return _process_parent(node)
    return None

def _extract_properties(project):
    properties_nodes = []
    for node in project.children:
        if node.label == labels.PROPERTIES:
            properties_nodes = node.children
    properties = {}
    for node in properties_nodes:
        properties[node.label] = node.content
    return properties

def _format_dependency(dep):
    result = "%s:%s:%s" % (dep.group_id, dep.artifact_id, dep.version)
    if bool(dep.classifier):
        type = dep.type if bool(dep.type) else "jar"
        result = "%s:%s" % (result, dep.type)
    elif bool(dep.type) and not dep.type == "jar":
        result = "%s:%s" % (result, dep.type)
    return result

def _parse(xml_text):
    root = xml.parse(xml_text)
    for node in root.children:
        if node.label == labels.PROJECT:
            return node
    fail("No <project> tag found in supplied xml: %s" % xml)

# A pom-specific node-merge algorith,
def _merge_content_last_wins(a, b):
    if not bool(a):
        return b
    elif not bool(b):
        return a
    else:
        if a.label != b.label:
            fail("Attempt to merge to different pom elements: %s, %s", (a, b))
        return xml.new_node(
            label = a.label,
            content = b.content if bool(b.content) else a.content,
        )

# This could be 100% reusable, except for the limit on recursion.  The strategy can't loop back and call this. :/
def _merge_leaf_elements(parent_list, child_list):
    index = {}
    merged = []
    for i in range(len(parent_list)):
        merged.append(parent_list[i])
        index[parent_list[i].label] = i
    for i in range(len(child_list)):
        index_of_property = index.get(child_list[i].label, -1)
        if index_of_property >= 0:
            merged[index_of_property] = child_list[i]
        else:
            merged.append(child_list[i])
            index[child_list[i].label] = len(merged)
    return merged

def _children_if_exists(node):
    return node.children if bool(node) else []

def _merge_properties_section(parent_node, child_node):
    if not bool(parent_node):
        return child_node
    elif not bool(child_node):
        return parent_node
    children = _merge_leaf_elements(
        _children_if_exists(xml.find_first(parent_node, labels.PROPERTIES)),
        _children_if_exists(xml.find_first(child_node, labels.PROPERTIES)),
    )
    return xml.new_node(label = labels.PROPERTIES, children = children)

# Description:
#   Merges the dependency section of the pom.  This makes an assumption that deps sections won't have both the main
#   artifact for a group_id/artifact_id pair AND one of the same pom's classified artifacts.  It is possible, and in
#   those cases, the deps will be wrong and the build snippet should be explicitly substituted.
def _merge_dependency_section(parent, child):
    if not bool(parent):
        return child if bool(child) else xml.new_node(label = labels.DEPENDENCIES)
    elif not bool(child):
        return parent if bool(parent) else xml.new_node(label = labels.DEPENDENCIES)
    if parent.label != labels.DEPENDENCIES:
        fail("Parent node in merged dependency operation not a <dependencies> node: %s" % parent)
    elif child.label != labels.DEPENDENCIES:
        fail("Child node in merged dependency operation not a <dependencies> node: %s" % child)

    # index the <dependency> nodes by groupId:artifactId
    parent_deps = {}
    for node in _children_if_exists(parent):
        key = "%s:%s" % (xml.find_first(node, labels.GROUP_ID), xml.find_first(node, labels.ARTIFACT_ID))
        parent_deps[key] = node
    child_deps = {}
    for node in _children_if_exists(child):
        key = "%s:%s" % (xml.find_first(node, labels.GROUP_ID), xml.find_first(node, labels.ARTIFACT_ID))
        child_deps[key] = node

    merged = {}
    for key in parent_deps:
        merged[key] = parent_deps[key]
    for key in child_deps:
        if bool(merged.get(key, None)):
            existing_node = merged[key]
            merged[key] = xml.new_node(
                label = labels.DEPENDENCY,
                children = _merge_leaf_elements(
                    _children_if_exists(merged[key]),
                    _children_if_exists(child_deps[key]),
                ),
            )
        else:
            merged[key] = child_deps[key]

    dependency_items = []
    for key, node in merged.items():
        dependency_items.append(node)
    return xml.new_node(
        label = labels.DEPENDENCIES,
        children = dependency_items,
    )

# A highly constrained merge (only merges core metadata, properties, dependency_management, and dependency sections.
# It drops all other sections on the floor, including parent pom metadata.  It is also not as efficient as it could be,
# because pom sections are unordered, so there's a lot of scanning.  It also requires lots of targetted methods since
# starlark has no recursion, so this code cannot be generalized without becoming a hellish batch of insane iteration.
def _merge_parent(parent, child):
    merged = xml.new_node(label = labels.PROJECT, children = [])

    # merge core identity metadata
    for label in [labels.GROUP_ID, labels.ARTIFACT_ID, labels.VERSION]:
        merged_node = _merge_content_last_wins(xml.find_first(parent, label), xml.find_first(child, label))
        if bool(merged_node):
            merged.children.append(merged_node)

    # merge packaging with jar special cased.
    child_packaging_node = xml.find_first(child, labels.PACKAGING)
    merged.children.append(
        child_packaging_node if bool(child_packaging_node) else xml.new_node(label = labels.PACKAGING, content = "jar"),
    )

    # merge properties
    merged.children.append(_merge_properties_section(parent, child))

    # merge dependencies
    merged.children.append(_merge_dependency_section(
        xml.find_first(parent, labels.DEPENDENCIES),
        xml.find_first(child, labels.DEPENDENCIES),
    ))

    # merge dependencyManagement->dependencies
    merged.children.append(xml.new_node(label = labels.DEPENDENCY_MANAGEMENT, children = [
        _merge_dependency_section(
            xml.find_first(parent, labels.DEPENDENCY_MANAGEMENT, labels.DEPENDENCIES),
            xml.find_first(child, labels.DEPENDENCY_MANAGEMENT, labels.DEPENDENCIES),
        ),
    ]))
    return merged

poms = struct(
    # Returns an xml element tree of the supplied pom text.
    parse = _parse,

    # Returns a list of structs containing the properties each dependency declared pom xml tree.
    extract_dependencies = _extract_dependencies,

    # Returns a list of structs each dependency declared in the dependencyManagement of the pom xml tree.
    extract_dependency_management = _extract_dependency_management,

    # Returns a struct containing the critical elements of a parent in the pom tree, sutable for pom fetching.
    extract_parent = _extract_parent,

    # Returns a dictionary containing the properties of the pom xml tree.
    extract_properties = _extract_properties,

    # Returns a string representation of the supplied dependency
    format_dependency = _format_dependency,

    # Merges a parent pom xml tree with a child xml tree.
    merge_parent = _merge_parent,
)
