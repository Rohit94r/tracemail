import React from "react";
import { Navbar } from "@/components/Navbar";
import { Hero } from "@/components/Hero";
import { BrandsMarquee } from "@/components/BrandsMarquee";
import { ProblemSection } from "@/components/ProblemSection";
import { FeaturesSection } from "@/components/FeaturesSection";
import { BenefitsSection } from "@/components/BenefitsSection";
import { DifferentiatorsSection } from "@/components/DifferentiatorsSection";
import { PricingSection } from "@/components/PricingSection";
import { TestimonialsSection } from "@/components/TestimonialsSection";
import { FAQSection } from "@/components/FAQSection";
import { BlogSection } from "@/components/BlogSection";
import { CTASection } from "@/components/CTASection";
import { Footer } from "@/components/Footer";

export default function Home() {
  return (
    <>
      <Navbar />
      <main>
        <Hero />
        <BrandsMarquee />
        <ProblemSection />
        <FeaturesSection />
        <BenefitsSection />
        <DifferentiatorsSection />
        <PricingSection />
        <TestimonialsSection />
        <FAQSection />
        <BlogSection />
        <CTASection />
      </main>
      <Footer />
    </>
  );
}
