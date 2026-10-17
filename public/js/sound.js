/**
 * Sentinel IDS - Cyber Audio Synthesizer (Zero External Audio Files)
 * Generates alarm pings, siren beeps and UI feedback via Web Audio API.
 */
class SoundEffects {
  constructor() {
    this.ctx = null;
    this.enabled = localStorage.getItem("sentinel_sound") !== "0";
  }

  init() {
    if (!this.ctx && (window.AudioContext || window.webkitAudioContext)) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      this.ctx = new AudioCtx();
    }
    if (this.ctx && this.ctx.state === "suspended") {
      this.ctx.resume();
    }
  }

  toggle() {
    this.enabled = !this.enabled;
    localStorage.setItem("sentinel_sound", this.enabled ? "1" : "0");
    if (this.enabled) this.playSuccess();
    return this.enabled;
  }

  playAlert(severity = "High") {
    if (!this.enabled) return;
    try {
      this.init();
      if (!this.ctx) return;
      const t = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      if (severity === "High") {
        // High severity dual-tone urgent alarm
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(880, t);
        osc.frequency.exponentialRampToValueAtTime(440, t + 0.15);
        osc.frequency.setValueAtTime(880, t + 0.2);
        osc.frequency.exponentialRampToValueAtTime(330, t + 0.4);

        gain.gain.setValueAtTime(0.15, t);
        gain.gain.exponentialRampToValueAtTime(0.01, t + 0.45);

        osc.start(t);
        osc.stop(t + 0.45);
      } else if (severity === "Medium") {
        // Medium severity warning chime
        osc.type = "triangle";
        osc.frequency.setValueAtTime(587.33, t); // D5
        osc.frequency.setValueAtTime(783.99, t + 0.1); // G5

        gain.gain.setValueAtTime(0.12, t);
        gain.gain.exponentialRampToValueAtTime(0.001, t + 0.3);

        osc.start(t);
        osc.stop(t + 0.3);
      } else {
        // Low severity subtle blip
        osc.type = "sine";
        osc.frequency.setValueAtTime(440, t);
        gain.gain.setValueAtTime(0.08, t);
        gain.gain.exponentialRampToValueAtTime(0.001, t + 0.15);
        osc.start(t);
        osc.stop(t + 0.15);
      }
    } catch (e) {
      console.warn("Sound error:", e);
    }
  }

  playSuccess() {
    if (!this.enabled) return;
    try {
      this.init();
      if (!this.ctx) return;
      const t = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.type = "sine";
      osc.frequency.setValueAtTime(523.25, t); // C5
      osc.frequency.exponentialRampToValueAtTime(1046.50, t + 0.2); // C6
      gain.gain.setValueAtTime(0.1, t);
      gain.gain.exponentialRampToValueAtTime(0.001, t + 0.25);
      osc.start(t);
      osc.stop(t + 0.25);
    } catch (e) {}
  }
}

window.sounds = new SoundEffects();
