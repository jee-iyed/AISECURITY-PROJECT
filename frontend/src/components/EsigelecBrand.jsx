import React, { useState } from "react";

// Local assets only. Prefer PNG, then SVG, WebP, and JPG.
const assets = import.meta.glob("../assets/esigelec-logo.{png,svg,webp,jpg}", {
  eager: true,
  query: "?url",
  import: "default",
});
const logos = ["png", "svg", "webp", "jpg"]
  .map((extension) => assets[`../assets/esigelec-logo.${extension}`])
  .filter(Boolean);

export default function EsigelecBrand({ size = "medium" }) {
  const [index, setIndex] = useState(0);
  const variant = ["small", "medium", "large"].includes(size) ? size : "medium";
  return (
    <div className={`esigelec-brand esigelec-brand--${variant}`}>
      {logos[index] ? (
        <img
          src={logos[index]}
          alt="ESIGELEC"
          onError={() => setIndex((value) => value + 1)}
        />
      ) : (
        <span className="esigelec-brand__fallback">ESIGELEC</span>
      )}
    </div>
  );
}
