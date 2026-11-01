
import ipaddress
import copy


# =========================================================
# 1. NETWORK INPUT VALIDATION
# =========================================================

def parse_ipv4_network(value, field_name):

    try:
        if isinstance(value, (ipaddress.IPv4Network,
                              ipaddress.IPv6Network)):
            network = value
        else:
            network = ipaddress.ip_network(value, strict=True)

    except (ValueError, TypeError) as error:
        return None, [f"INVALID {field_name}: {error}"]

    if network.version != 4:
        return None, [f"{field_name} must be IPv4"]

    return network, []


def validate_host_requirement(required_hosts):

    return (
        isinstance(required_hosts, int)
        and not isinstance(required_hosts, bool)
        and required_hosts > 0
    )


# =========================================================
# 2. REQUIRED SUBNET PREFIX
# =========================================================

def recommend_prefix(required_hosts):

    if not validate_host_requirement(required_hosts):
        return None

    for prefix in range(30, -1, -1):

        usable_hosts = (2 ** (32 - prefix)) - 2

        if usable_hosts >= required_hosts:
            return prefix

    return None


# =========================================================
# 3. EXISTING ALLOCATION VALIDATION
# =========================================================

def validate_allocations(pool_cidr, allocations):

    errors = []
    conflicts = []
    valid_networks = []
    names = set()

    pool, pool_errors = parse_ipv4_network(
        pool_cidr, "POOL"
    )

    if pool_errors:
        return None, [], pool_errors, []

    if not isinstance(allocations, list):

        return (
            None,
            [],
            ["Allocations must be a list"],
            []
        )

    for allocation in allocations:

        if not isinstance(allocation, dict):

            errors.append(
                f"INVALID ALLOCATION RECORD: {allocation}"
            )
            continue

        name = allocation.get("name")
        cidr = allocation.get("cidr")
        required_hosts = allocation.get("required_hosts")

        # Validate name

        if not isinstance(name, str) or not name.strip():

            errors.append(
                "Allocation name must be a non-empty string"
            )

        else:

            normalized_name = name.strip().casefold()

            if normalized_name in names:

                errors.append(
                    f"DUPLICATE ALLOCATION NAME: {name}"
                )

            names.add(normalized_name)

        # Validate CIDR

        subnet, subnet_errors = parse_ipv4_network(
            cidr, f"CIDR FOR {name}"
        )

        if subnet_errors:

            errors.extend(subnet_errors)
            continue

        # Validate pool containment

        if not subnet.subnet_of(pool):

            errors.append(
                f"OUTSIDE POOL: {name} - {subnet}"
            )
            continue

        # Conventional host calculation:
        # /31 and /32 are excluded in this exercise.

        if subnet.prefixlen > 30:

            errors.append(
                f"UNSUPPORTED PREFIX: {name} - {subnet}"
            )

        # Validate required capacity

        if not validate_host_requirement(required_hosts):

            errors.append(
                f"INVALID HOST REQUIREMENT: {name}"
            )

        elif subnet.prefixlen <= 30:

            usable_hosts = subnet.num_addresses - 2

            if usable_hosts < required_hosts:

                errors.append(
                    f"INSUFFICIENT CAPACITY: {name} - "
                    f"requires {required_hosts}, "
                    f"provides {usable_hosts}"
                )

        valid_networks.append(subnet)

    # Detect every pairwise overlap

    for i in range(len(valid_networks)):

        for j in range(i + 1, len(valid_networks)):

            network_a = valid_networks[i]
            network_b = valid_networks[j]

            if network_a.overlaps(network_b):

                conflicts.append(
                    f"{network_a} overlaps {network_b}"
                )

    return pool, valid_networks, errors, conflicts


# =========================================================
# 4. OVERLAP CHECKER
# =========================================================

def check_overlap(candidate, allocations):

    candidate, errors = parse_ipv4_network(
        candidate, "CANDIDATE"
    )

    if errors:
        return [], errors

    if not isinstance(allocations, list):

        return [], ["Allocations must be a list"]

    conflicts = []

    for allocation in allocations:

        existing, parse_errors = parse_ipv4_network(
            allocation, "ALLOCATION"
        )

        if parse_errors:

            errors.extend(parse_errors)
            continue

        if candidate.overlaps(existing):

            conflicts.append(
                f"{candidate} overlaps {existing}"
            )

    return conflicts, errors


# =========================================================
# 5. CANDIDATE VALIDATION
# =========================================================

def validate_candidate(candidate, pool, allocations):

    candidate, errors = parse_ipv4_network(
        candidate, "CANDIDATE"
    )

    if errors:
        return False, errors, []

    pool, pool_errors = parse_ipv4_network(
        pool, "POOL"
    )

    if pool_errors:
        return False, pool_errors, []

    if not candidate.subnet_of(pool):

        return (
            False,
            ["Candidate is outside the authorised pool"],
            []
        )

    if candidate.prefixlen > 30:

        return (
            False,
            ["Candidate prefix is unsupported"],
            []
        )

    conflicts, errors = check_overlap(
        candidate, allocations
    )

    if errors or conflicts:

        return False, errors, conflicts

    return True, [], []


# =========================================================
# 6. FREE ADDRESS-SPACE CALCULATION
# =========================================================

def find_free_space(pool, allocations):

    pool, errors = parse_ipv4_network(
        pool, "POOL"
    )

    if errors:
        return None, errors, []

    if not isinstance(allocations, list):

        return None, ["Allocations must be a list"], []

    validated_allocations = []
    conflicts = []

    for allocation in allocations:

        subnet, subnet_errors = parse_ipv4_network(
            allocation, "ALLOCATION"
        )

        if subnet_errors:

            errors.extend(subnet_errors)
            continue

        if not subnet.subnet_of(pool):

            errors.append(
                f"ALLOCATION OUTSIDE POOL: {subnet}"
            )
            continue

        validated_allocations.append(subnet)

    # Check every allocation pair

    for i in range(len(validated_allocations)):

        for j in range(i + 1, len(validated_allocations)):

            network_a = validated_allocations[i]
            network_b = validated_allocations[j]

            if network_a.overlaps(network_b):

                conflicts.append(
                    f"{network_a} overlaps {network_b}"
                )

    if errors or conflicts:

        return None, errors, conflicts

    # Calculate free address space

    free_space = [pool]

    for subnet in validated_allocations:

        updated_free_space = []

        for free_network in free_space:

            if subnet.subnet_of(free_network):

                remaining = free_network.address_exclude(
                    subnet
                )

                updated_free_space.extend(remaining)

            else:

                updated_free_space.append(free_network)

        free_space = updated_free_space

    free_space.sort(
        key=lambda network: int(network.network_address)
    )

    return free_space, [], []


# =========================================================
# 7. BEST FIT RECOMMENDATION
# =========================================================

def recommend_subnet(
    free_space,
    required_hosts,
    allocations,
    pool
):

    prefix = recommend_prefix(required_hosts)

    if prefix is None:

        return (
            None,
            ["Invalid or unsupported host requirement"],
            []
        )

    if not isinstance(free_space, list):

        return None, ["Free space must be a list"], []

    suitable_blocks = []

    for block in free_space:

        network, errors = parse_ipv4_network(
            block, "FREE SPACE BLOCK"
        )

        if errors:
            return None, errors, []

        if network.subnet_of(pool):

            if network.prefixlen <= prefix:

                suitable_blocks.append(network)

    # Best Fit: smallest suitable block first

    suitable_blocks.sort(
        key=lambda block: (
            -block.prefixlen,
            int(block.network_address)
        )
    )

    encountered_conflicts = []

    for block in suitable_blocks:

        if block.prefixlen == prefix:

            candidates = [block]

        else:

            candidates = block.subnets(
                new_prefix=prefix
            )

        for candidate in candidates:

            valid, errors, conflicts = validate_candidate(
                candidate,
                pool,
                allocations
            )

            if errors:

                return None, errors, conflicts

            if valid:

                return candidate, [], []

            encountered_conflicts.extend(conflicts)

    if encountered_conflicts:

        return (
            None,
            ["Free-space data contains conflicting candidates"],
            encountered_conflicts
        )

    return (
        None,
        ["No suitable free subnet is available"],
        []
    )


# =========================================================
# 8. ADDRESS-SPACE ACCOUNTING
# =========================================================

def verify_address_space(pool, allocations, free_space):

    errors = []

    allocated_addresses = sum(
        network.num_addresses
        for network in allocations
    )

    free_addresses = sum(
        network.num_addresses
        for network in free_space
    )

    # Verify containment

    for network in allocations + free_space:

        if not network.subnet_of(pool):

            errors.append(
                f"Network outside pool: {network}"
            )

    # Verify no allocated networks overlap

    for i in range(len(allocations)):

        for j in range(i + 1, len(allocations)):

            if allocations[i].overlaps(allocations[j]):

                errors.append(
                    f"Allocated networks overlap: "
                    f"{allocations[i]} / {allocations[j]}"
                )

    # Verify no free networks overlap each other

    for i in range(len(free_space)):

        for j in range(i + 1, len(free_space)):

            if free_space[i].overlaps(free_space[j]):

                errors.append(
                    f"Free networks overlap: "
                    f"{free_space[i]} / {free_space[j]}"
                )

    # Verify free space does not overlap allocations

    for free_network in free_space:

        for allocated_network in allocations:

            if free_network.overlaps(allocated_network):

                errors.append(
                    f"Free space overlaps allocation: "
                    f"{free_network} / {allocated_network}"
                )

    # Verify total address count

    if allocated_addresses + free_addresses != pool.num_addresses:

        errors.append("Address-space accounting mismatch")

    if errors:
        return False, errors

    return True, []


# =========================================================
# 9. COMPLETE ALLOCATION WORKFLOW
# =========================================================

def plan_allocation(
    pool_cidr,
    allocations,
    new_name,
    required_hosts
):

    original_allocations = copy.deepcopy(allocations)

    # Validate proposed department name

    if not isinstance(new_name, str) or not new_name.strip():

        return {
            "status": "REJECTED",
            "errors": ["Invalid allocation name"]
        }

    new_name = new_name.strip()
    normalized_new_name = new_name.casefold()

    # Validate requested host capacity

    prefix = recommend_prefix(required_hosts)

    if prefix is None:

        return {
            "status": "REJECTED",
            "errors": ["Invalid or unsupported host requirement"]
        }

    # Validate existing configuration

    pool, networks, errors, conflicts = validate_allocations(
        pool_cidr,
        allocations
    )

    if errors or conflicts:

        return {
            "status": "REJECTED",
            "errors": errors,
            "conflicts": conflicts,
            "original_preserved": (
                allocations == original_allocations
            )
        }

    # EARLY DUPLICATE NAME CHECK

    existing_names = {
        allocation["name"].strip().casefold()
        for allocation in allocations
    }

    if normalized_new_name in existing_names:

        return {
            "status": "REJECTED",
            "errors": [
                f"Department already exists: {new_name}"
            ],
            "original_preserved": (
                allocations == original_allocations
            )
        }

    # Calculate current free space

    free_before, errors, conflicts = find_free_space(
        pool, networks
    )

    if errors or conflicts:

        return {
            "status": "REJECTED",
            "errors": errors,
            "conflicts": conflicts
        }

    # Verify current address accounting

    valid, errors = verify_address_space(
        pool, networks, free_before
    )

    if not valid:

        return {
            "status": "REJECTED",
            "errors": errors
        }

    # Recommend a subnet

    candidate, errors, conflicts = recommend_subnet(
        free_before,
        required_hosts,
        networks,
        pool
    )

    if candidate is None:

        status = (
            "REJECTED"
            if conflicts or "conflicting" in " ".join(errors).lower()
            else "NO CAPACITY"
        )

        return {
            "status": status,
            "errors": errors,
            "conflicts": conflicts,
            "free_before": free_before,
            "original_preserved": (
                allocations == original_allocations
            )
        }

    # Independently validate candidate

    valid, errors, conflicts = validate_candidate(
        candidate,
        pool,
        networks
    )

    if not valid:

        return {
            "status": "REJECTED",
            "errors": errors,
            "conflicts": conflicts
        }

    # Simulate allocation using a deep copy

    proposed_allocations = copy.deepcopy(
        original_allocations
    )

    proposed_allocations.append({

        "name": new_name,
        "cidr": str(candidate),
        "required_hosts": required_hosts

    })

    # Revalidate entire proposed configuration

    proposed_pool, proposed_networks, errors, conflicts = (
        validate_allocations(
            pool_cidr,
            proposed_allocations
        )
    )

    if errors or conflicts:

        return {
            "status": "REJECTED",
            "errors": errors,
            "conflicts": conflicts,
            "original_preserved": (
                allocations == original_allocations
            )
        }

    # Calculate resulting free space

    free_after, errors, conflicts = find_free_space(
        proposed_pool,
        proposed_networks
    )

    if errors or conflicts:

        return {
            "status": "REJECTED",
            "errors": errors,
            "conflicts": conflicts
        }

    # Verify resulting address accounting

    valid, errors = verify_address_space(
        proposed_pool,
        proposed_networks,
        free_after
    )

    if not valid:

        return {
            "status": "REJECTED",
            "errors": errors
        }

    # Confirm original configuration is unchanged

    original_preserved = (
        allocations == original_allocations
    )

    if not original_preserved:

        return {
            "status": "REJECTED",
            "errors": ["Original configuration was modified"]
        }

    return {

        "status": "ACCEPTED",
        "name": new_name,
        "candidate": candidate,
        "prefix": prefix,
        "required_hosts": required_hosts,
        "free_before": free_before,
        "free_after": free_after,
        "original_preserved": original_preserved,
        "proposed_allocations": proposed_allocations

    }


# =========================================================
# 10. REPORTING
# =========================================================

def display_report(result):

    print("\n========== ALLOCATION REPORT ==========")

    print("STATUS:", result["status"])

    if result["status"] == "ACCEPTED":

        print("Department:", result["name"])
        print("Recommended subnet:", result["candidate"])
        print("Required hosts:", result["required_hosts"])
        print("Recommended prefix:", f"/{result['prefix']}")

        print("\nFREE SPACE BEFORE:")

        for network in result["free_before"]:
            print(network)

        print("\nFREE SPACE AFTER:")

        for network in result["free_after"]:
            print(network)

        print("\nPROPOSED CONFIGURATION:")

        for allocation in result["proposed_allocations"]:
            print(allocation)

        print(
            "\nOriginal configuration preserved:",
            result["original_preserved"]
        )

    else:

        print("\nERRORS:")

        for error in result.get("errors", []):
            print("-", error)

        print("\nCONFLICTS:")

        for conflict in result.get("conflicts", []):
            print("-", conflict)


# =========================================================
# 11. AUTOMATED TEST SUITE
# =========================================================

def run_tests():

    pool = "10.20.30.0/24"

    original = [

        {
            "name": "HR",
            "cidr": "10.20.30.160/27",
            "required_hosts": 12
        },

        {
            "name": "IT",
            "cidr": "10.20.30.192/26",
            "required_hosts": 50
        }

    ]

    tests = []

    def record(name, condition):
        tests.append((name, bool(condition)))

    # TEST 1: Successful allocation

    result = plan_allocation(
        pool, original, "FINANCE", 50
    )

    record(
        "Successful allocation",
        result["status"] == "ACCEPTED"
        and str(result["candidate"]) == "10.20.30.0/26"
        and result["original_preserved"]
    )

    # TEST 2: Correct free-space calculation

    record(
        "Correct remaining free space",
        [str(n) for n in result["free_after"]]
        == ["10.20.30.64/26", "10.20.30.128/27"]
    )

    # TEST 3: Existing overlap

    overlap_config = copy.deepcopy(original)
    overlap_config[0]["cidr"] = "10.20.30.192/27"

    result = plan_allocation(
        pool, overlap_config, "FINANCE", 50
    )

    record(
        "Existing overlap rejected",
        result["status"] == "REJECTED"
        and len(result["conflicts"]) > 0
    )

    # TEST 4: Outside pool

    outside_config = copy.deepcopy(original)
    outside_config[0]["cidr"] = "192.168.1.0/27"

    result = plan_allocation(
        pool, outside_config, "FINANCE", 50
    )

    record(
        "Outside-pool allocation rejected",
        result["status"] == "REJECTED"
        and any("OUTSIDE POOL" in e for e in result["errors"])
    )

    # TEST 5: Invalid CIDR

    invalid_config = copy.deepcopy(original)
    invalid_config[0]["cidr"] = "INVALID-CIDR"

    result = plan_allocation(
        pool, invalid_config, "FINANCE", 50
    )

    record(
        "Invalid CIDR rejected",
        result["status"] == "REJECTED"
    )

    # TEST 6: Insufficient capacity

    result = plan_allocation(
        pool, original, "FINANCE", 200
    )

    record(
        "Insufficient capacity detected",
        result["status"] == "NO CAPACITY"
    )

    # TEST 7: Zero host requirement

    result = plan_allocation(
        pool, original, "FINANCE", 0
    )

    record(
        "Zero host requirement rejected",
        result["status"] == "REJECTED"
    )

    # TEST 8: IPv6 allocation

    ipv6_config = copy.deepcopy(original)
    ipv6_config[0]["cidr"] = "2001:db8::/64"

    result = plan_allocation(
        pool, ipv6_config, "FINANCE", 50
    )

    record(
        "IPv6 allocation rejected",
        result["status"] == "REJECTED"
    )

    # TEST 9: IPv6 pool

    result = plan_allocation(
        "2001:db8::/64", original, "FINANCE", 50
    )

    record(
        "IPv6 pool rejected",
        result["status"] == "REJECTED"
    )

    # TEST 10: Duplicate existing names

    duplicate_config = copy.deepcopy(original)

    duplicate_config.append({
        "name": "HR",
        "cidr": "10.20.30.0/26",
        "required_hosts": 50
    })

    result = plan_allocation(
        pool, duplicate_config, "FINANCE", 50
    )

    record(
        "Duplicate existing name rejected",
        result["status"] == "REJECTED"
        and any("DUPLICATE" in e for e in result["errors"])
    )

    # TEST 11: Missing required field

    malformed_config = copy.deepcopy(original)
    del malformed_config[0]["required_hosts"]

    result = plan_allocation(
        pool, malformed_config, "FINANCE", 50
    )

    record(
        "Missing host requirement rejected",
        result["status"] == "REJECTED"
    )

    # TEST 12: Invalid allocation structure

    result = plan_allocation(
        pool, ["INVALID RECORD"], "FINANCE", 50
    )

    record(
        "Invalid allocation structure rejected",
        result["status"] == "REJECTED"
    )

    # TEST 13: Original configuration unchanged

    before = copy.deepcopy(original)

    result = plan_allocation(
        pool, original, "FINANCE", 50
    )

    record(
        "Original configuration preserved",
        original == before and result["original_preserved"]
    )

    # TEST 14: New department name duplicate
    # Check is case-insensitive.

    result = plan_allocation(
        pool, original, "hr", 50
    )

    record(
        "New duplicate name rejected early",
        result["status"] == "REJECTED"
        and "Department already exists: hr" in result["errors"]
    )

    # TEST 15: Separate overlap results and parse errors

    conflicts, errors = check_overlap(
        "10.20.30.128/26",
        [
            "10.20.30.128/27",
            "INVALID-CIDR",
            "10.20.30.160/27"
        ]
    )

    record(
        "Conflicts and errors separated",
        len(conflicts) == 2 and len(errors) == 1
    )

    # TEST 16: Multiple conflicts reported

    conflicts, errors = check_overlap(
        "10.20.30.128/25",
        [
            "10.20.30.128/27",
            "10.20.30.160/27"
        ]
    )

    record(
        "Multiple overlaps detected",
        len(conflicts) == 2 and len(errors) == 0
    )

    # Display results

    print("\n========== AUTOMATED TEST RESULTS ==========")

    passed = 0

    for name, success in tests:

        print(
            f"{'PASS' if success else 'FAIL'}: {name}"
        )

        if success:
            passed += 1

    print("\nTOTAL:", len(tests))
    print("PASSED:", passed)
    print("FAILED:", len(tests) - passed)

    if passed == len(tests):
        print("\nALL TESTS PASSED")

    else:
        print("\nSOME TESTS FAILED")

    return passed == len(tests)


# =========================================================
# 12. MAIN EXECUTION
# =========================================================

if __name__ == "__main__":

    pool = "10.20.30.0/24"

    allocations = [

        {
            "name": "HR",
            "cidr": "10.20.30.160/27",
            "required_hosts": 12
        },

        {
            "name": "IT",
            "cidr": "10.20.30.192/26",
            "required_hosts": 50
        }

    ]

    result = plan_allocation(
        pool,
        allocations,
        "FINANCE",
        50
    )

    display_report(result)

    run_tests()
