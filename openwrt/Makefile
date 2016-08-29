# 
# Copyright (C) 2006-2016 SCUT Router Term
#
# This is free software, licensed under the GNU Affero General Public License v3.
# See /COPYING for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=scutclient
PKG_VERSION:=1.6
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

PKG_LICENSE:=AGPLv3

PKG_FIXUP:=autoreconf
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/scutclient
  SECTION:=net
  CATEGORY:=Network
  TITLE:=SCUT Dr.com client
  DEPENDS:=
  URL:=
endef

define Package/scutclient/description
 Support SCUT private authentication protocol.
endef

define Package/scutclient/config
if PACKAGE_scutclient
config PACKAGE_SCUTCLIENT_LUCI
	bool "	Build with LuCI intergrated"
	default y
endif
endef


TARGET_CFLAGS += \
	-ffunction-sections \
	-fdata-sections

CONFIGURE_VARS += \
	ac_cv_linux_vers=$(LINUX_VERSION) \
	ac_cv_header_libusb_1_0_libusb_h=no \
	ac_cv_netfilter_can_compile=no


CONFIGURE_ARGS += \
	--enable-shared \
	--enable-static \
	--disable-yydebug \
	--enable-ipv6 \
	--with-build-cc="$(HOSTCC)" \
	--with-pcap=linux \
	--without-septel \
	--without-dag \
	--without-libnl \
	--disable-can

define Build/Prepare
$(call Build/Prepare/Default)
endef

define Build/Configure
$(call Build/Configure/Default)
endef

define Package/scutclient/postinst
endef

define Package/scutclient/conffiles
/etc/config/scutclient
endef


define Package/scutclient/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/scutclient.config $(1)/etc/config/scutclient
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/scutclient.init $(1)/etc/init.d/scutclient
	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) ./files/scutclient.hotplug $(1)/etc/hotplug.d/iface/95-scutclient
#	$(MAKE) -C $(PKG_BUILD_DIR) install-exec DESTDIR=$(1)
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scutclient $(1)/usr/bin

ifeq ($(CONFIG_PACKAGE_SCUTCLIENT_LUCI),y)
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/scutclient 
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi/scutclient	 
	$(INSTALL_BIN) ./files/luci/view-logs.htm $(1)/usr/lib/lua/luci/view/scutclient/logs.htm
	$(INSTALL_BIN) ./files/luci/view-status.htm $(1)/usr/lib/lua/luci/view/scutclient/status.htm
	$(INSTALL_BIN) ./files/luci/controller-scutclient.lua $(1)/usr/lib/lua/luci/controller/scutclient.lua
	$(INSTALL_BIN) ./files/luci/model-scutclient.lua $(1)/usr/lib/lua/luci/model/cbi/scutclient/scutclient.lua
endif

endef

$(eval $(call BuildPackage,scutclient))
