# choose-apply-environment.py

Run by each plan job after the spend gate. It prints `production-free` only
when every input is exactly the good value. Every other input, missing or
odd, picks `production`, where the owner approves. The rule and its reasons
are in `decide()`.

It reads the four inputs from the environment, never from arguments, so
nothing the plan produced is parsed as a flag. It writes the choice to the
GitHub output and summary files it is given.

An exit status other than 0 writes nothing. The workflow reads an unset output
as `production`, so a crash here also lands on the owner's environment.
