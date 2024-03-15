"""
description: Environment is cleared and passed
outer_env:
    key1: outer-value1
    key2: outer-value2
script: |
    expect(run(Run(argv, env={
        "key1": "inner-value1",
        "key3": "inner-value3",
    })))
"""

import os

assert os.environ.get("key1") == "inner-value1", "Unexpected key1 value"
assert "key2" not in os.environ, "key2 is present"
assert os.environ.get("key3") == "inner-value3", "Unexpected key3 value"
