export interface StrengthResult {
    score: number; // 0-4
    label: string;
    color: string;
    feedback: string[];
}

export const analyzePasswordStrength = (password: string): StrengthResult => {
    let score = 0;
    const feedback: string[] = [];

    if (!password) {
        return { score: 0, label: "Empty", color: "bg-slate-700", feedback: [] };
    }

    // 1. Length Check
    if (password.length > 8) score += 1;
    if (password.length > 12) score += 1;
    if (password.length < 8) feedback.push("Too short (aim for 8+ chars)");

    // 2. Complexity Check
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);

    if (hasUpper && hasLower) score += 1;
    else if (!hasUpper) feedback.push("Add uppercase letters");
    else if (!hasLower) feedback.push("Add lowercase letters");

    if (hasNumber || hasSpecial) score += 1;
    if (!hasNumber) feedback.push("Add numbers");
    if (!hasSpecial) feedback.push("Add special characters");

    // Cap score at 4
    if (score > 4) score = 4;

    // Determine Label & Color
    let label = "Weak";
    let color = "bg-red-500";

    switch (score) {
        case 0:
        case 1:
            label = "Weak";
            color = "bg-red-500";
            break;
        case 2:
            label = "Fair";
            color = "bg-yellow-500";
            break;
        case 3:
            label = "Good";
            color = "bg-blue-500";
            break;
        case 4:
            label = "Strong";
            color = "bg-emerald-500";
            break;
    }

    return { score, label, color, feedback };
};
