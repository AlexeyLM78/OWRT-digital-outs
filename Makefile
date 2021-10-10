SECTION="NetPing modules"
CATEGORY="Base"
TITLE="EPIC7 OWRT_Digital_outs"

PKG_NAME="OWRT_Digital_outs"
PKG_VERSION="Epic7.V1.S1"
PKG_RELEASE=1

CONF_FILES=owrt_digital_outs
CONF_DIR=/etc/config/

ETC_FILES=owrt_digital_outs.py
ETC_FILES_DIR=/etc/netping_digital_outs/

CLI_COMMANDS_DIR=commands
CLI_HELP_FILE=Help

.PHONY: all install

all: install

install:
	for f in $(CONF_FILES); do cp $${f} $(CONF_DIR); done
	mkdir $(ETC_FILES_DIR)
	for f in $(ETC_FILES); do cp etc/$${f} $(ETC_FILES_DIR); done
	cp -r $(CLI_COMMANDS_DIR) $(CLI_HELP_FILE) $(ETC_FILES_DIR)

clean:
	for f in $(CONF_FILES); do rm -f $(CONF_DIR)$${f}; done
	rm -rf $(ETC_FILES_DIR)
