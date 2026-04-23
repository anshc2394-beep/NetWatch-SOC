/* onboarding.js — Demo Mode Guided Tutorial */

console.log('onboarding.js loaded');

const TOUR_STORAGE_DONE = 'netwatch_demo_tour_completed';
const TOUR_STORAGE_PENDING = 'netwatch_demo_tour_pending';

const DEMO_TOUR_STEPS = [
    {
        target: '#tour-overview',
        title: 'System Overview',
        text: 'This command center gives you a single-pane view of traffic rhythm, alerts, and risk so you can manage the SOC with confidence.',
        allowBack: false
    },
    {
        target: '#tour-rhythm',
        title: 'Network Rhythm',
        text: 'Tracks packet flow consistency and highlights sudden deviations that often precede scanning or automated attacks.'
    },
    {
        target: '#tour-density',
        title: 'Anomaly Density',
        text: 'Shows the number of unusual flows compared to baseline behavior. A rising density means the model is seeing more potential threats.'
    },
    {
        target: '#tour-risk',
        title: 'SOC Risk Score',
        text: 'A real-time risk index based on active anomaly counts and abnormal traffic signatures.',
    },
    {
        target: '#chart-traffic',
        title: 'Traffic Volume',
        text: 'This chart shows total packet volume over time, which helps you identify suspicious spikes and protocol shifts.',
    },
    {
        target: '#tour-topology',
        title: 'Talkers & Topology',
        text: 'A quick map of active hosts and relationships. It helps reveal whether a suspicious endpoint is isolated or part of a broader peer cluster.',
    },
    {
        target: '#tour-alerts',
        title: 'Alert Feed',
        text: 'This pane lists flagged flows. Each entry is a candidate for investigation and requires your attention in the SOC workflow.',
    },
    {
        target: 'click-first-anomaly',
        selector: '#flow-tbody tr:first-child',
        title: 'Inspect a Suspect Flow',
        text: 'Click the first flagged flow to open the investigation page and see the anomaly details.',
        interactive: true
    }
];

const INVESTIGATION_TOUR_STEPS = [
    {
        target: '#tour-investigation',
        title: 'Investigation Insight',
        text: 'This page surfaces the most important metadata for the flagged flow so you can make a fast, accurate decision.',
        allowBack: true
    },
    {
        target: '#tour-return',
        title: 'Transition to Real Monitoring',
        text: 'Return to the SOC dashboard and switch from demo mode to real monitoring when you are ready.',
        allowBack: true,
        final: true
    }
];

let tourBackdrop = null;
let tourBox = null;
let tourTarget = null;
let currentTour = null;
let currentStepIndex = 0;
let interactionHandler = null;

function isDemoMode() {
    return (typeof IS_DEMO !== 'undefined' && (IS_DEMO === true || IS_DEMO === 'true'))
        || (typeof window !== 'undefined' && window.IS_DEMO === true)
        || (typeof window !== 'undefined' && window.IS_DEMO === 'true');
}

function hasTourCompleted() {
    return localStorage.getItem(TOUR_STORAGE_DONE) === 'true';
}

function markTourCompleted() {
    localStorage.setItem(TOUR_STORAGE_DONE, 'true');
}

function resetTourCompleted() {
    localStorage.removeItem(TOUR_STORAGE_DONE);
}

function setInvestigationPending() {
    localStorage.setItem(TOUR_STORAGE_PENDING, 'investigation');
}

function getInvestigationPending() {
    return localStorage.getItem(TOUR_STORAGE_PENDING);
}

function clearInvestigationPending() {
    localStorage.removeItem(TOUR_STORAGE_PENDING);
}

function initDemoTour() {
    console.log('initDemoTour called, isDemoMode:', isDemoMode());
    if (!isDemoMode()) return;

    const pending = getInvestigationPending();
    if (pending === 'investigation') {
        clearInvestigationPending();
        startTour('investigation');
        return;
    }

    if (hasTourCompleted()) return;
    if (document.querySelector('#flow-tbody tr')) {
        startTour('dashboard');
        return;
    }

    const waitForData = setInterval(() => {
        if (document.querySelector('#flow-tbody tr')) {
            clearInterval(waitForData);
            if (!hasTourCompleted()) {
                startTour('dashboard');
            }
        }
    }, 400);
}

function createTourElements() {
    if (tourBackdrop && tourBox) return;
    tourBackdrop = document.createElement('div');
    tourBackdrop.className = 'tour-backdrop';
    document.body.appendChild(tourBackdrop);

    tourBox = document.createElement('div');
    tourBox.className = 'tour-box';
    tourBox.innerHTML = '';
    document.body.appendChild(tourBox);

    setTimeout(() => {
        tourBackdrop.classList.add('active');
        tourBox.classList.add('active');
    }, 30);
}

function startTour(mode = 'dashboard') {
    if (!isDemoMode()) return;
    currentTour = mode === 'investigation' ? INVESTIGATION_TOUR_STEPS : DEMO_TOUR_STEPS;
    currentStepIndex = 0;
    createTourElements();
    showCurrentStep();
}

function getCurrentStep() {
    return currentTour[currentStepIndex];
}

function getTargetElement(step) {
    if (!step) return null;
    if (step.target === 'click-first-anomaly') {
        return document.querySelector(step.selector) || document.querySelector('#flow-tbody tr');
    }
    return document.querySelector(step.target);
}

function highlightElement(element) {
    clearHighlight();
    if (!element) return;
    tourTarget = element;
    element.classList.add('tour-focus');
    element.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
}

function clearHighlight() {
    if (tourTarget) {
        if (interactionHandler) {
            tourTarget.removeEventListener('click', interactionHandler);
            interactionHandler = null;
        }
        tourTarget.classList.remove('tour-focus');
        tourTarget = null;
    }
}

function showCurrentStep() {
    const step = getCurrentStep();
    if (!step) {
        finishTour();
        return;
    }

    const target = getTargetElement(step);
    if (!target && !step.interactive) {
        nextStep();
        return;
    }

    highlightElement(target);
    if (step.interactive && target) {
        attachInteractiveStep(target);
    }
    updateTourBox(step);
}

function attachInteractiveStep(element) {
    if (!element) return;
    if (interactionHandler) {
        element.removeEventListener('click', interactionHandler);
        interactionHandler = null;
    }
    interactionHandler = () => {
        setInvestigationPending();
    };
    element.addEventListener('click', interactionHandler, { once: true });
}

function updateTourBox(step) {
    if (!tourBox) return;
    const stepLabel = `Step ${currentStepIndex + 1} of ${currentTour.length}`;
    const showBack = currentStepIndex > 0 && step.allowBack !== false;
    const showNext = !step.interactive;
    const nextLabel = step.final ? 'Finish' : 'Next';

    tourBox.innerHTML = `
        <div class="tour-header">
            <div class="tour-step">${stepLabel}</div>
            <button type="button" class="tour-link" id="tour-skip-btn">Skip Tutorial</button>
        </div>
        <div class="tour-title">${step.title}</div>
        <div class="tour-copy">${step.text}</div>
        <div class="tour-actions">
            ${showBack ? '<button type="button" class="tour-btn tour-btn--secondary" id="tour-back-btn">Back</button>' : ''}
            ${showNext ? `<button type="button" class="tour-btn tour-btn--primary" id="tour-next-btn">${nextLabel}</button>` : `<button type="button" class="tour-btn tour-btn--primary" disabled id="tour-next-btn">${step.interactive ? 'Click to Continue' : nextLabel}</button>`}
        </div>
    `;

    // Attach event listeners
    const skipBtn = tourBox.querySelector('#tour-skip-btn');
    if (skipBtn) {
        skipBtn.addEventListener('click', skipDemoTour);
    }

    const backBtn = tourBox.querySelector('#tour-back-btn');
    if (backBtn) {
        backBtn.addEventListener('click', prevDemoStep);
    }

    const nextBtn = tourBox.querySelector('#tour-next-btn');
    if (nextBtn && !nextBtn.disabled) {
        nextBtn.addEventListener('click', nextDemoStep);
    }
}

window.nextDemoStep = function() {
    console.log('nextDemoStep called');
    const step = getCurrentStep();
    if (step && step.interactive) return;
    if (currentStepIndex >= currentTour.length - 1) {
        finishTour();
        return;
    }
    currentStepIndex += 1;
    showCurrentStep();
};

window.prevDemoStep = function() {
    console.log('prevDemoStep called');
    if (currentStepIndex === 0) return;
    currentStepIndex -= 1;
    showCurrentStep();
};

window.skipDemoTour = function() {
    console.log('skipDemoTour called');
    finishTour(true);
};

function finishTour(skip = false) {
    if (tourBox) tourBox.remove();
    if (tourBackdrop) tourBackdrop.remove();
    clearHighlight();
    currentTour = null;
    currentStepIndex = 0;
    tourBox = null;
    tourBackdrop = null;
    if (!skip) {
        markTourCompleted();
    } else {
        markTourCompleted();
    }
}

window.restartDemoTour = function() {
    resetTourCompleted();
    clearInvestigationPending();
    if (tourBox || tourBackdrop) {
        finishTour(true);
    }
    startTour('dashboard');
};

window.startTour = startTour;

const currentPath = window.location.pathname;
if (currentPath.startsWith('/dashboard')) {
    document.addEventListener('DOMContentLoaded', () => {
        console.log('DOMContentLoaded for dashboard');
        initDemoTour();
    });
} else if (currentPath.startsWith('/anomaly/')) {
    document.addEventListener('DOMContentLoaded', () => {
        console.log('DOMContentLoaded for anomaly');
        initDemoTour();
    });
}
