# test_branchleft_deploy.py

Narrative moved out of `test_branchleft_deploy.py` under the CMT-3 gate
(comment blocks of 11 lines or more). Each section is cited from a one-line
pointer in the code, by its heading.

## PinnedImageIsUpTests

the image this call just pinned, as opposed to some other service in the
same stack. This is the fact the MySQL data-dictionary-downgrade case
turns on: mysqld starting cleanly on the new image while an unrelated
exporter fails its healthcheck must read as "the image is fine."
