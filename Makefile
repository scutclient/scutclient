# 
# Copyright (C) 2006-2008 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=scutclient
PKG_RELEASE:=4
PKG_VERSION:=1.4
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz

include $(INCLUDE_DIR)/package.mk

define Package/scutclient
  SECTION:=net
  CATEGORY:=Network
  TITLE:=SCUT 802.1X client by Forward
 DEPENDS:=libc 
endef

define Package/scutclient/description
 Support SCUT private authentication protocol.
 Thanks to njit8021xclient made by liuqun.
endef

CONFIGURE_ARGS += \
		$(NULL)

define Build/Prepare
$(call Build/Prepare/Default)
endef

define Build/Configure
$(call Build/Configure/Default)
endef

define Package/scutclient/install
	$(MAKE) -C $(PKG_BUILD_DIR) install-exec DESTDIR=$(1) libpcap.a
endef

$(eval $(call BuildPackage,scutclient))
