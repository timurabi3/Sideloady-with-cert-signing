// Sideloadly-Cert Interactive Stage, Qt5 Simulator & Scroll Fallback
(function () {
  "use strict";

  // 1. Fallback for browsers without CSS scroll-driven animations (modern-web-guidance shrinking-header-on-scroll)
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  if (
    !CSS.supports("(animation-timeline: scroll()) and (animation-range: 0% 100%)") &&
    !reduceMotion.matches
  ) {
    const header = document.querySelector(".site-header");
    if (header) {
      const initialHeight = 76;
      const finalHeight = 58;
      const scrollDistance = 120;
      window.addEventListener(
        "scroll",
        function () {
          const scrollPercent = Math.min(1, window.scrollY / scrollDistance);
          const newHeight = initialHeight - (initialHeight - finalHeight) * scrollPercent;
          header.style.height = newHeight + "px";
        },
        { passive: true }
      );
    }
  }

  // 2. Hero Layered Depth Rig (pointer tilt + spotlight + screenshot view switcher)
  const rig = document.getElementById("hero-rig");
  const screenshotImg = document.getElementById("hero-screenshot");
  const stageCaption = document.getElementById("stage-caption-text");
  const stageTabs = document.querySelectorAll(".stage-tab");

  const views = {
    overview: {
      src: "./assets/sideloadly-cert-overview.png",
      alt: "Sideloadly-Cert v0.72 full macOS window with Apple Developer Certificate panel expanded under Advanced Options",
      caption: "Full macOS window: Apple ID selector bound to local .p12 certificate"
    },
    panel: {
      src: "./assets/sideloadly-cert-panel.png",
      alt: "Close-up of the Apple Developer Certificate (.p12 + .mobileprovision) group box inside Sideloadly Advanced Options",
      caption: "Advanced Options close-up: .p12 + .mobileprovision drop zone and status bar"
    }
  };

  stageTabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      const targetView = tab.getAttribute("data-view");
      if (!views[targetView] || !screenshotImg) return;

      stageTabs.forEach(function (t) {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");

      screenshotImg.src = views[targetView].src;
      screenshotImg.alt = views[targetView].alt;
      if (stageCaption) {
        stageCaption.textContent = views[targetView].caption;
      }
    });
  });

  if (rig && !reduceMotion.matches) {
    rig.addEventListener("pointermove", function (e) {
      const rect = rig.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width;
      const y = (e.clientY - rect.top) / rect.height;
      const rotateY = (x - 0.5) * 5.5;
      const rotateX = (0.5 - y) * 4.5;

      rig.style.setProperty("--spot-x", Math.round(x * 100) + "%");
      rig.style.setProperty("--spot-y", Math.round(y * 100) + "%");
      rig.style.transform =
        "rotateX(" + rotateX.toFixed(2) + "deg) rotateY(" + rotateY.toFixed(2) + "deg)";
    });

    rig.addEventListener("pointerleave", function () {
      rig.style.transform = "rotateX(0deg) rotateY(0deg)";
    });
  }

  // 3. Interactive Qt5 Certificate Drop-Zone Simulator
  const presets = {
    indie: {
      team: "Northstar Labs GmbH",
      teamId: "9K4L8M2P7Q",
      days: "342d",
      expDate: "2027-10-12",
      udids: "4",
      p12Path: "~/Certs/northstar_dist_2027.p12",
      provPath: "~/Certs/northstar_adhoc.mobileprovision",
      passHint: "Auto-loaded from PASSWORD.txt"
    },
    personal: {
      team: "Studio Horizon Dev",
      teamId: "4X8V2N9C1W",
      days: "289d",
      expDate: "2027-08-20",
      udids: "1",
      p12Path: "~/Desktop/apple_dev_cert/dev_signing.p12",
      provPath: "~/Desktop/apple_dev_cert/iphone17pro.mobileprovision",
      passHint: "Verified PKCS#12 MAC"
    },
    enterprise: {
      team: "Aether Mobile Core",
      teamId: "7P3R9T5W2K",
      days: "364d",
      expDate: "2027-11-03",
      udids: "18",
      p12Path: "/Volumes/SecureKey/aether_ios_dev.p12",
      provPath: "/Volumes/SecureKey/aether_wildcard.mobileprovision",
      passHint: "Keychain unlocked"
    }
  };

  const simCombo = document.getElementById("sim-account-combo");
  const simBanner = document.getElementById("sim-status-banner");
  const simP12 = document.getElementById("sim-p12-input");
  const simProv = document.getElementById("sim-prov-input");
  const simPass = document.getElementById("sim-pass-input");
  const presetButtons = document.querySelectorAll(".cert-preset-chip");
  const verifyBtn = document.getElementById("sim-verify-btn");
  const clearBtn = document.getElementById("sim-clear-btn");
  const replicaBox = document.getElementById("qt5-replica-box");

  function applyProfile(profile) {
    if (!simCombo || !simBanner || !simP12 || !simProv || !simPass) return;
    simCombo.textContent =
      "[Cert] " + profile.team + " (" + profile.teamId + ") : " + profile.p12Path.split("/").pop();
    simBanner.classList.remove("unconfigured");
    simBanner.textContent =
      "✓ Active: " +
      profile.team +
      " (" +
      profile.teamId +
      ") | Expires: " +
      profile.expDate +
      " (" +
      profile.days +
      ") | UDIDs: " +
      profile.udids;
    simP12.value = profile.p12Path;
    simProv.value = profile.provPath;
    simPass.value = "••••••••••••";
    simPass.setAttribute("title", profile.passHint);
  }

  presetButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      const key = btn.getAttribute("data-preset");
      if (!presets[key]) return;
      presetButtons.forEach(function (b) {
        b.classList.remove("active");
      });
      btn.classList.add("active");
      applyProfile(presets[key]);
    });
  });

  if (verifyBtn) {
    verifyBtn.addEventListener("click", function () {
      const p12Val = (simP12 && simP12.value.trim()) || "~/Certs/custom_dev.p12";
      const fileName = p12Val.split("/").pop() || "custom_dev.p12";
      simBanner.classList.remove("unconfigured");
      simBanner.textContent =
        "✓ Active: Custom Developer Identity (8F2D9K4M1B) | Expires: 2027-11-04 (365d) | UDIDs: 1";
      simCombo.textContent = "[Cert] Custom Developer Identity (8F2D9K4M1B) : " + fileName;
    });

    document.querySelectorAll('[data-sim-trigger="verify"]').forEach(function (triggerBtn) {
      triggerBtn.addEventListener("click", function () {
        verifyBtn.click();
      });
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", function () {
      presetButtons.forEach(function (b) {
        b.classList.remove("active");
      });
      simBanner.classList.add("unconfigured");
      simBanner.textContent = "Drop .p12 + .mobileprovision here or click Upload below";
      simCombo.textContent = "[Cert] Active Developer Certificate";
      simP12.value = "";
      simProv.value = "";
      simPass.value = "";
    });
  }

  // Real browser drag-and-drop file inspection on the replica panel
  if (replicaBox) {
    ["dragenter", "dragover"].forEach(function (evtName) {
      replicaBox.addEventListener(evtName, function (e) {
        e.preventDefault();
        replicaBox.classList.add("drag-over");
      });
    });

    ["dragleave", "drop"].forEach(function (evtName) {
      replicaBox.addEventListener(evtName, function (e) {
        e.preventDefault();
        replicaBox.classList.remove("drag-over");
      });
    });

    replicaBox.addEventListener("drop", function (e) {
      const files = Array.from((e.dataTransfer && e.dataTransfer.files) || []);
      if (!files.length) return;
      files.forEach(function (f) {
        const lower = f.name.toLowerCase();
        if (lower.endsWith(".p12") || lower.endsWith(".pfx")) {
          simP12.value = f.name;
        } else if (lower.endsWith(".mobileprovision") || lower.endsWith(".provisionprofile")) {
          simProv.value = f.name;
        }
      });
      if (verifyBtn) verifyBtn.click();
    });
  }

  // 4. Terminal command copy button
  const copyBtn = document.getElementById("copy-terminal-btn");
  const cmdText = document.getElementById("terminal-cmd-text");
  if (copyBtn && cmdText) {
    copyBtn.addEventListener("click", function () {
      const raw = cmdText.innerText.trim();
      navigator.clipboard.writeText(raw).then(function () {
        const prev = copyBtn.textContent;
        copyBtn.textContent = "Copied ✓";
        setTimeout(function () {
          copyBtn.textContent = prev;
        }, 1800);
      });
    });
  }
})();

