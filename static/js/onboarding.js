/**
 * onboarding.js — Professional SOC Guided Tour
 * Spotlight focus mode + Manual Navigation + Advanced Content
 */

const TOUR_STEPS = [
    { 
        target: "tour-rhythm", 
        title: "Ingress Telemetry Rhythm",
        text: "Real-time moving-window analysis of packet frequency. This module monitors through-put consistency to detect low-latency flood vectors and volumetric jitter." 
    },
    { 
        target: "tour-density", 
        title: "Divergence Density",
        text: "Isolation Forest results mapped into a statistical density field. High alert counts signify recursive feature divergence where packets are fundamentally 'few and different' from the learned baseline." 
    },
    { 
        target: "tour-insights", 
        title: "Heuristic Intuition Agent",
        text: "Autonomous reasoning engine that correlates 5-tuple metadata (Src/Dst, Port, Protocol) into actionable plain-English security intelligence." 
    },
    { 
        target: "tour-forensic", 
        title: "Temporal Normality Forensics",
        text: "A 4th-dimensional view of system health. Red-shifted troughs in the normality curve represent high-severity anomalies detected during active feature extraction." 
    },
    { 
        target: "tour-alerts", 
        title: "Forensic Incident Feed",
        text: "Real-time queue of high-risk flow clusters. Each entry represents a unique network conversation that has breached the established normality threshold." 
    },
    { 
        target: "tour-flows", 
        title: "Flow Cluster Matrix",
        text: "Deep packet inspection (DPI) summaries grouped by CIDR and protocol. Use this matrix to perform rapid forensic correlations across active host sessions." 
    },
    { 
        target: "tour-topology", 
        title: "Relational Topology Graph",
        text: "Mapping active peering relationships and hop-by-hop connections. Visualizes the relational gravity between internal assets and external endpoints." 
    }
];

let currentStep = 0;
let tourOverlay = null;
let tourBackdrop = null;

window.initTour = function() {
    if (localStorage.getItem('soc_tour_completed')) return;
    
    // Check if we have data rows yet
    if (document.querySelectorAll('#flow-tbody tr').length < 2) {
        setTimeout(window.initTour, 1000);
        return;
    }
    startTour();
};

function startTour() {
    // Create Backdrop
    tourBackdrop = document.createElement('div');
    tourBackdrop.className = 'tour-backdrop';
    document.body.appendChild(tourBackdrop);
    
    // Create Tour Box
    tourOverlay = document.createElement('div');
    tourOverlay.className = 'tour-box';
    document.body.appendChild(tourOverlay);

    // Activate
    setTimeout(() => tourBackdrop.classList.add('active'), 100);
    showStep();
}

function showStep() {
    const step = TOUR_STEPS[currentStep];
    const el = document.getElementById(step.target);
    
    if (!el) {
        nextStep();
        return;
    }

    // Reset previous spotlights
    document.querySelectorAll('.tour-spotlight').forEach(node => node.classList.remove('tour-spotlight'));
    
    // Apply Spotlight
    el.classList.add('tour-spotlight');
    el.scrollIntoView({ behavior: 'smooth', block: 'center' });

    const rect = el.getBoundingClientRect();
    
    // Position Tour Box
    tourOverlay.style.top = (rect.bottom + window.scrollY + 20) + 'px';
    tourOverlay.style.left = Math.max(20, rect.left) + 'px';
    
    // Check if it goes off screen bottom
    if (rect.bottom + 300 > window.innerHeight + window.scrollY) {
        tourOverlay.style.top = (rect.top + window.scrollY - 280) + 'px';
    }

    tourOverlay.innerHTML = `
        <div style="font-weight: 800; color: var(--accent-cyan); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.8rem; letter-spacing: 1px;">
            Step ${currentStep + 1} of ${TOUR_STEPS.length}
        </div>
        <div style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.8rem; color: #fff;">${step.title}</div>
        <div style="line-height: 1.6; color: var(--text-muted);">${step.text}</div>
        <div class="tour-btns">
            <button class="tour-btn" onclick="prevStep()" ${currentStep === 0 ? 'disabled' : ''}>Back</button>
            <button class="tour-btn tour-btn--next" onclick="nextStep()">
                ${currentStep === TOUR_STEPS.length - 1 ? 'Finish' : 'Next'}
            </button>
        </div>
    `;
}

window.nextStep = function() {
    currentStep++;
    if (currentStep >= TOUR_STEPS.length) {
        finishTour();
    } else {
        showStep();
    }
};

window.prevStep = function() {
    if (currentStep > 0) {
        currentStep--;
        showStep();
    }
};

window.finishTour = function() {
    if (tourOverlay) tourOverlay.remove();
    if (tourBackdrop) tourBackdrop.remove();
    document.querySelectorAll('.tour-spotlight').forEach(node => node.classList.remove('tour-spotlight'));
    localStorage.setItem('soc_tour_completed', 'true');
};

if (document.getElementById('tour-rhythm')) {
    window.initTour();
}
