"""
description: Files are preserved after commit
script: |
    def simple_run(i):
        expect(run(input=str(i), context=str(i)))
        run_reset()

    simple_run(0)

    run(input="1")
    commit()
    run_reset()

    simple_run(2)
    simple_run(3)
"""

import os

run = int(input())

if run == 0:
    with open("/space/run0", "w") as f:
        f.write("Run 0")
elif run == 1:
    assert not os.path.exists("/space/run0")
    with open("/space/run1", "w") as f:
        f.write("Run 1")
elif run == 2:
    assert not os.path.exists("/space/run0")
    with open("/space/run1") as f:
        assert f.read() == "Run 1"
    with open("/space/run2", "w") as f:
        f.write("Run 2")
else:
    assert not os.path.exists("/space/run0")
    with open("/space/run1") as f:
        assert f.read() == "Run 1"
    assert not os.path.exists("/space/run2")
