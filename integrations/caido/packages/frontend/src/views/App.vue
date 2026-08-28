<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

import {
  DEFAULT_BRIDGE_SETTINGS,
  type BridgeSettings,
  type DaemonStatus,
} from "mimic-caido-shared";

import { availableProfiles, formatUptime } from "../model.js";
import type { FrontendSDK } from "../types.js";

const props = defineProps<{ sdk: FrontendSDK }>();

const settings = ref<BridgeSettings>({ ...DEFAULT_BRIDGE_SETTINGS });
const status = ref<DaemonStatus | null>(null);
const loading = ref(true);
const saving = ref(false);
const refreshing = ref(false);
const switching = ref(false);
const error = ref("");
const notice = ref("");
const selectedProfile = ref("");

const profiles = computed(() => availableProfiles(status.value, settings.value.profileOverride));
const healthLabel = computed(() => (status.value === null ? "Unavailable" : "Connected"));

function showError(value: string): void {
  error.value = value;
  notice.value = "";
}

async function refreshStatus(showFailure = true): Promise<void> {
  if (refreshing.value) return;
  refreshing.value = true;
  try {
    const result = await props.sdk.backend.getStatus();
    if (result.kind === "Error") {
      status.value = null;
      if (showFailure) showError(result.error);
      return;
    }
    status.value = result.value;
    selectedProfile.value = result.value.profile;
    if (showFailure) error.value = "";
  } catch (cause) {
    status.value = null;
    if (showFailure) showError(cause instanceof Error ? cause.message : String(cause));
  } finally {
    refreshing.value = false;
  }
}

async function load(): Promise<void> {
  loading.value = true;
  try {
    const result = await props.sdk.backend.getSettings();
    if (result.kind === "Error") {
      showError(result.error);
    } else {
      settings.value = { ...result.value };
    }
    await refreshStatus(true);
  } catch (cause) {
    showError(cause instanceof Error ? cause.message : String(cause));
  } finally {
    loading.value = false;
  }
}

async function save(): Promise<void> {
  saving.value = true;
  error.value = "";
  notice.value = "";
  try {
    const result = await props.sdk.backend.saveSettings({ ...settings.value });
    if (result.kind === "Error") {
      showError(result.error);
      return;
    }
    settings.value = { ...result.value };
    notice.value = "Bridge settings saved";
    props.sdk.window.showToast("Mimic settings saved", { variant: "success" });
    await refreshStatus(true);
  } catch (cause) {
    showError(cause instanceof Error ? cause.message : String(cause));
  } finally {
    saving.value = false;
  }
}

async function useProfile(): Promise<void> {
  if (selectedProfile.value === "") return;
  switching.value = true;
  error.value = "";
  notice.value = "";
  try {
    const result = await props.sdk.backend.useProfile(selectedProfile.value);
    if (result.kind === "Error") {
      showError(result.error);
      return;
    }
    status.value = result.value;
    selectedProfile.value = result.value.profile;
    notice.value = `Daemon profile changed to ${result.value.profile}`;
    props.sdk.window.showToast(notice.value, { variant: "success" });
  } catch (cause) {
    showError(cause instanceof Error ? cause.message : String(cause));
  } finally {
    switching.value = false;
  }
}

let poll: ReturnType<typeof setInterval> | undefined;
onMounted(async () => {
  await load();
  poll = setInterval(() => void refreshStatus(false), 10_000);
});
onBeforeUnmount(() => {
  if (poll !== undefined) clearInterval(poll);
});
</script>

<template>
  <main class="mimic-page">
    <header class="hero">
      <div>
        <p class="eyebrow">UPSTREAM TRANSPORT IDENTITY</p>
        <h1>Mimic</h1>
        <p class="lede">
          Keep Caido's editing workflow while Mimic owns the final TLS and HTTP presentation.
        </p>
      </div>
      <div class="health" :class="{ online: status !== null }" aria-live="polite">
        <span class="health-dot" aria-hidden="true"></span>
        {{ healthLabel }}
      </div>
    </header>

    <div v-if="loading" class="panel loading">Loading Mimic settings…</div>

    <template v-else>
      <div v-if="error" class="message error" role="alert">{{ error }}</div>
      <div v-if="notice" class="message notice" role="status">{{ notice }}</div>

      <section class="metrics" aria-label="Mimic daemon status">
        <article class="metric">
          <span>Active profile</span>
          <strong>{{ status?.profile ?? "—" }}</strong>
        </article>
        <article class="metric">
          <span>Requests</span>
          <strong>{{ status?.requests ?? "—" }}</strong>
        </article>
        <article class="metric">
          <span>Connections</span>
          <strong>{{ status?.connections ?? "—" }}</strong>
        </article>
        <article class="metric">
          <span>TLS fallbacks</span>
          <strong>{{ status?.tls_fallbacks ?? "—" }}</strong>
        </article>
        <article class="metric">
          <span>Uptime</span>
          <strong>{{ status ? formatUptime(status.uptime_seconds) : "—" }}</strong>
        </article>
      </section>

      <div class="layout">
        <section class="panel">
          <div class="panel-heading">
            <div>
              <h2>Daemon profile</h2>
              <p>Change the default profile live for new upstream connections.</p>
            </div>
            <button class="button secondary" :disabled="refreshing" @click="refreshStatus()">
              {{ refreshing ? "Checking…" : "Check status" }}
            </button>
          </div>

          <div class="inline-control">
            <label for="active-profile">Active profile</label>
            <select id="active-profile" v-model="selectedProfile" :disabled="status === null">
              <option v-for="profile in status?.profiles ?? []" :key="profile" :value="profile">
                {{ profile }}
              </option>
            </select>
            <button
              class="button primary"
              :disabled="status === null || switching || selectedProfile === status?.profile"
              @click="useProfile"
            >
              {{ switching ? "Applying…" : "Use profile" }}
            </button>
          </div>

          <dl v-if="status" class="details">
            <div><dt>Control endpoint</dt><dd>{{ settings.controlHost }}:{{ settings.controlPort }}</dd></div>
            <div><dt>Configuration</dt><dd>{{ status.config_path }}</dd></div>
            <div><dt>Profiles loaded</dt><dd>{{ status.profiles.length }}</dd></div>
          </dl>
        </section>

        <section class="panel">
          <div class="panel-heading">
            <div>
              <h2>Bridge settings</h2>
              <p>Stored by the backend and applied before each selected Caido connection.</p>
            </div>
            <label class="switch-label">
              <input v-model="settings.enabled" type="checkbox" />
              <span>{{ settings.enabled ? "Enabled" : "Disabled" }}</span>
            </label>
          </div>

          <div class="form-grid">
            <label>
              Bridge host
              <select v-model="settings.bridgeHost">
                <option value="127.0.0.1">127.0.0.1</option>
                <option value="localhost">localhost</option>
                <option value="::1">::1</option>
              </select>
            </label>
            <label>
              Bridge port
              <input v-model.number="settings.bridgePort" type="number" min="1" max="65535" />
            </label>
            <label>
              Control host
              <select v-model="settings.controlHost">
                <option value="127.0.0.1">127.0.0.1</option>
                <option value="localhost">localhost</option>
                <option value="::1">::1</option>
              </select>
            </label>
            <label>
              Control port
              <input v-model.number="settings.controlPort" type="number" min="1" max="65535" />
            </label>
            <label class="wide">
              Bridge profile override
              <select v-model="settings.profileOverride">
                <option value="">Use Mimic routes and daemon default</option>
                <option v-for="profile in profiles" :key="profile" :value="profile">
                  {{ profile }}
                </option>
              </select>
              <small>
                Applies to every domain currently using the plugin. Leave empty to preserve Mimic
                host routes.
              </small>
            </label>
          </div>

          <div class="actions">
            <button class="button primary" :disabled="saving" @click="save">
              {{ saving ? "Saving…" : "Save settings" }}
            </button>
          </div>
        </section>
      </div>

      <aside class="callout">
        <strong>Domain opt-in still applies.</strong>
        Enable <em>Mimic Upstream</em> only for intended domains in Caido's Upstream Plugins
        settings. Disabling the bridge here returns those connections to Caido's normal upstream
        handling. Mimic must run on the same host as Caido; remote control endpoints are rejected.
      </aside>
    </template>
  </main>
</template>

<style scoped>
.mimic-page {
  box-sizing: border-box;
  max-width: 1180px;
  margin: 0 auto;
  padding: 32px;
  color: inherit;
  font-family: inherit;
}

.hero,
.panel-heading,
.inline-control,
.actions {
  display: flex;
  align-items: center;
}

.hero {
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 24px;
}

.eyebrow {
  margin: 0 0 6px;
  color: #8b5cf6;
  font-size: 0.72rem;
  font-weight: 800;
  letter-spacing: 0.13em;
}

h1,
h2,
p {
  margin-top: 0;
}

h1 {
  margin-bottom: 6px;
  font-size: 2rem;
  line-height: 1;
}

h2 {
  margin-bottom: 5px;
  font-size: 1.05rem;
}

.lede,
.panel-heading p,
small {
  margin-bottom: 0;
  opacity: 0.7;
}

.health {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border: 1px solid currentColor;
  border-radius: 999px;
  color: #ef4444;
  font-size: 0.82rem;
  font-weight: 700;
}

.health.online {
  color: #22c55e;
}

.health-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 10px currentColor;
}

.message,
.callout,
.panel,
.metric {
  border: 1px solid color-mix(in srgb, currentColor 15%, transparent);
  border-radius: 10px;
  background: color-mix(in srgb, currentColor 4%, transparent);
}

.message {
  margin-bottom: 16px;
  padding: 11px 14px;
}

.message.error {
  border-color: color-mix(in srgb, #ef4444 55%, transparent);
  color: #ef4444;
}

.message.notice {
  border-color: color-mix(in srgb, #22c55e 55%, transparent);
}

.metrics {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.metric {
  min-width: 0;
  padding: 15px;
}

.metric span {
  display: block;
  margin-bottom: 8px;
  opacity: 0.65;
  font-size: 0.72rem;
  font-weight: 700;
  text-transform: uppercase;
}

.metric strong {
  display: block;
  overflow: hidden;
  font-size: 1.05rem;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.layout {
  display: grid;
  grid-template-columns: 1fr 1.15fr;
  gap: 16px;
}

.panel {
  padding: 20px;
}

.panel-heading {
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 20px;
}

.inline-control {
  align-items: end;
  gap: 10px;
}

.inline-control label,
.form-grid label {
  display: grid;
  gap: 7px;
  font-size: 0.78rem;
  font-weight: 700;
}

.inline-control label {
  display: none;
}

.inline-control select {
  flex: 1;
}

input,
select,
button {
  box-sizing: border-box;
  font: inherit;
}

input,
select {
  width: 100%;
  min-height: 38px;
  padding: 8px 10px;
  border: 1px solid color-mix(in srgb, currentColor 22%, transparent);
  border-radius: 7px;
  background: color-mix(in srgb, currentColor 6%, transparent);
  color: inherit;
}

.button {
  min-height: 38px;
  padding: 8px 13px;
  border: 1px solid transparent;
  border-radius: 7px;
  cursor: pointer;
  font-weight: 700;
}

.button.primary {
  background: #7c3aed;
  color: white;
}

.button.secondary {
  border-color: color-mix(in srgb, currentColor 22%, transparent);
  background: transparent;
  color: inherit;
}

.button:disabled {
  cursor: not-allowed;
  opacity: 0.45;
}

.details {
  display: grid;
  gap: 10px;
  margin: 20px 0 0;
  padding-top: 16px;
  border-top: 1px solid color-mix(in srgb, currentColor 12%, transparent);
  font-size: 0.78rem;
}

.details div {
  display: grid;
  grid-template-columns: 120px minmax(0, 1fr);
  gap: 10px;
}

.details dt {
  opacity: 0.62;
}

.details dd {
  overflow-wrap: anywhere;
  margin: 0;
}

.switch-label {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 0.82rem;
  font-weight: 700;
}

.switch-label input {
  width: 17px;
  min-height: 17px;
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 14px;
}

.form-grid .wide {
  grid-column: 1 / -1;
}

.actions {
  justify-content: flex-end;
  margin-top: 18px;
}

.callout {
  margin-top: 16px;
  padding: 14px 16px;
  font-size: 0.82rem;
  line-height: 1.55;
}

.loading {
  text-align: center;
  opacity: 0.7;
}

@media (max-width: 900px) {
  .metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .layout {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 600px) {
  .mimic-page {
    padding: 20px;
  }

  .hero,
  .panel-heading,
  .inline-control {
    align-items: stretch;
    flex-direction: column;
  }

  .health {
    align-self: flex-start;
  }

  .form-grid,
  .metrics {
    grid-template-columns: 1fr;
  }
}
</style>
