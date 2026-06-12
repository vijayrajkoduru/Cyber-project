"""firmware tier6_hardware - advisory-by-design coverage for physical-access
techniques (UART/JTAG/SWD, side-channel/fault injection, chip-off acquisition).

These playbook techniques REQUIRE physical possession of the device, bench
hardware (JTAGulator, ChipWhisperer, BusPirate, logic analyser, chip-off
rework), and lab adjacency. They cannot be performed by an external SaaS
against an uploaded firmware blob and are emitted as honest INFO advisories
with an [ADVISORY-BY-DESIGN] marker — never as graded findings.
"""
