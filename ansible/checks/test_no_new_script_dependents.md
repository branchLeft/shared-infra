# test_no_new_script_dependents.py: no new caller of a pending-role script

A tracked file depends on a `pending-role` script when its text names the script's path or its
basename, and a shared basename counts for each script that carries it.
`hand_installers_dependents.yml` maps each dependent file to the sorted scripts it names. The test
fails on a new dependency, on a file that names one with no row, on a row naming a script the file
no longer names, and on a row for a file that is gone. The baseline only shrinks; it is edited by
hand, never regenerated.
