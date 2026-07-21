"use strict";
// Live preview + client-side validation for the OAuth2 app-icon upload
// (admin_oauth2_view_partial.html). Gives immediate feedback on format, file
// size and dimensions before the upload is sent, and blocks obviously-invalid
// files so the server never has to reject them. Mirrors the server limits in
// views/admin/oauth2.rs (MAX_IMAGE_UPLOAD_BYTES / MAX_IMAGE_UPLOAD_DIMENSION).

const OAUTH2_IMG_MAX_BYTES = 256 * 1024;
const OAUTH2_IMG_MAX_DIM = 1024;
const OAUTH2_IMG_TYPES = [
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/svg+xml",
  "image/webp",
];

function oauth2ImageInit() {
  const input = document.getElementById("oauth2-image-file");
  if (!input || input.dataset.previewBound === "1") {
    return;
  }
  input.dataset.previewBound = "1";

  const preview = document.getElementById("oauth2-image-preview");
  const meta = document.getElementById("oauth2-image-meta");
  const warn = document.getElementById("oauth2-image-warn");
  const uploadBtn = document.getElementById("oauth2-image-upload-btn");

  const setValid = (ok) => {
    if (uploadBtn) uploadBtn.disabled = !ok;
  };
  const showWarn = (msg) => {
    if (warn) {
      warn.textContent = msg;
      warn.classList.toggle("d-none", !msg);
    }
  };
  const reset = () => {
    if (preview) {
      preview.classList.add("d-none");
      if (preview.dataset.objurl) {
        URL.revokeObjectURL(preview.dataset.objurl);
        delete preview.dataset.objurl;
      }
      preview.removeAttribute("src");
    }
    if (meta) meta.textContent = "";
    showWarn("");
  };

  input.addEventListener("change", () => {
    reset();
    const file = input.files && input.files[0];
    if (!file) {
      setValid(true);
      return;
    }

    const kb = Math.round(file.size / 1024);
    const problems = [];
    if (!OAUTH2_IMG_TYPES.includes(file.type)) {
      problems.push(
        `Unsupported type "${file.type || "unknown"}" — use PNG, JPG, GIF, SVG or WebP.`,
      );
    }
    if (file.size > OAUTH2_IMG_MAX_BYTES) {
      problems.push(`Too large: ${kb} KB (max ${OAUTH2_IMG_MAX_BYTES / 1024} KB).`);
    }

    const objurl = URL.createObjectURL(file);
    if (preview) {
      preview.dataset.objurl = objurl;
      preview.src = objurl;
      preview.classList.remove("d-none");
    }

    // SVGs have no meaningful raster dimensions; only dimension-check rasters.
    if (file.type !== "image/svg+xml") {
      const probe = new Image();
      probe.onload = () => {
        const w = probe.naturalWidth;
        const h = probe.naturalHeight;
        if (w > OAUTH2_IMG_MAX_DIM || h > OAUTH2_IMG_MAX_DIM) {
          problems.push(`Too big: ${w}×${h}px (max ${OAUTH2_IMG_MAX_DIM}×${OAUTH2_IMG_MAX_DIM}px).`);
        }
        if (meta) meta.textContent = `${w}×${h}px · ${kb} KB`;
        showWarn(problems.join(" "));
        setValid(problems.length === 0);
      };
      probe.onerror = () => {
        if (meta) meta.textContent = `${kb} KB`;
        problems.push("File doesn't look like a valid image.");
        showWarn(problems.join(" "));
        setValid(false);
      };
      probe.src = objurl;
    } else {
      if (meta) meta.textContent = `${kb} KB`;
      showWarn(problems.join(" "));
      setValid(problems.length === 0);
    }
  });
}

// The oauth2 view is loaded/replaced via HTMX, so (re)bind after each settle
// as well as on initial page load.
document.addEventListener("DOMContentLoaded", oauth2ImageInit);
document.body.addEventListener("htmx:afterSettle", oauth2ImageInit);
