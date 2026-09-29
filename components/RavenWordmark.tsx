"use client";

import React, { useState } from "react";
import { motion, useReducedMotion } from "framer-motion";

const GLYPHS = ["R", "A", "V", "E", "N"] as const;

const TILT = [-4, 4, -3, 4, -4];

export function RavenWordmark() {
  const [active, setActive] = useState<number | null>(null);
  const reduceMotion = useReducedMotion();

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6">
      <h2 className="sr-only">Raven</h2>
      <div
        aria-hidden="true"
        className="raven-wordmark"
        style={{ fontSize: "clamp(56px, 28vw, 400px)" }}
      >
        {GLYPHS.map((glyph, index) => {
          const isActive = active === index;

          return (
            <motion.span
              key={glyph}
              className="raven-letter"
              data-glyph={glyph}
              data-active={isActive}
              onHoverStart={() => setActive(index)}
              onHoverEnd={() =>
                setActive((current) => (current === index ? null : current))
              }
              initial={reduceMotion ? false : { y: "0.42em", opacity: 0, rotate: 10 }}
              animate={{ y: 0, opacity: 1, rotate: 0 }}
              transition={{
                delay: 0.07 * index,
                type: "spring",
                stiffness: 130,
                damping: 13,
                mass: 0.7,
              }}
              whileHover={
                reduceMotion
                  ? undefined
                  : {
                      y: "-0.12em",
                      scale: 1.07,
                      rotate: TILT[index],
                    }
              }
              whileTap={reduceMotion ? undefined : { y: "-0.02em", scale: 0.96 }}
            >
              {glyph}
            </motion.span>
          );
        })}
      </div>
    </div>
  );
}
