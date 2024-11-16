vals = [499, 399, 299, 199]
final = 7174

seen = set()

def rec(total, config):
    if total == final:
        return config
    elif total > final:
        return None
    elif tuple(config) in seen:
        return None
    
    best = 10e9
    c = None
    for i, val in enumerate(vals):
        nxt_config = list(config)
        nxt_config[i] += 1

        curr = rec(total + val, nxt_config)
        seen.add(tuple(nxt_config))
        if curr and sum(curr) < best:
            best = sum(curr)
            c = curr
    return c

r = rec(0, [0, 0, 0, 0])
print(r)

# [6, 1, 0, 19]
