"use strict";

const $ = (id) => document.getElementById(id);
const state = { token: null, username: "", hall: null, revision: null, catalog: null,
  selected: null, view: "overview", mode: "login", busy: false, online: false };
const containerNames = { warehouse: "仓库", backpack: "背包", equipment: "装备" };
const statusNames = { available: "可领取", locked: "未解锁", accepted: "进行中", completed: "待领奖", claimed: "已领取" };
const errors = {
  UNAUTHORIZED: "账号或密码错误，或登录已失效。请重新登录。", ACCOUNT_EXISTS: "这个用户名已被注册，请登录或换一个用户名。",
  INVALID_ARGUMENT: "请检查填写的内容，用户名需为字母、数字、中文或 . _ -，密码至少 8 个字符。",
  STALE_REVISION: "存档刚刚发生变化，已刷新数据，请重新操作。", POSITION_OCCUPIED: "这个位置已有物品，请选择空格。",
  OUT_OF_BOUNDS: "物品放不下，请调整位置或旋转物品。", INVALID_STACK_SPLIT: "拆分数量必须小于当前堆叠数量。",
  INVALID_EQUIPMENT: "这个物品不能装备到主武器栏。", SLOT_OCCUPIED: "主武器栏已有物品，请先将它移回仓库。",
  WAREHOUSE_FULL: "仓库已满，请整理出空间后再领取奖励。", QUEST_LOCKED: "请先完成前置任务并领取奖励。",
  INVALID_QUEST_STATE: "任务状态已经变化，请刷新后重试。", OBJECTIVES_INCOMPLETE: "任务目标尚未完成。",
  INVALID_SUBMISSION: "提交数量超出物品数量或剩余任务目标。", WRONG_QUEST_ITEM: "请选择符合目标的物品。",
  INTERNAL_ERROR: "本地服务未能完成操作，请稍后重试。", NOT_FOUND: "物品或任务已发生变化，请刷新数据。"
};

function node(tag, props = {}, children = []) {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "className") element.className = value;
    else if (key === "text") element.textContent = value;
    else if (key === "onClick") element.addEventListener("click", value);
    else if (key === "disabled") element.disabled = value;
    else element.setAttribute(key, String(value));
  }
  for (const child of children) element.append(child);
  return element;
}
function pretty(name) { return String(name || "").replace(/^开发用/, "本地").replace(/^开发验证：/, "本地任务："); }
function itemName(template) { return pretty(state.catalog?.items[template]?.name || template); }
function toast(message, error = false) {
  $("toast").textContent = message; $("toast").classList.toggle("error", error); $("toast").hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { $("toast").hidden = true; }, 5500);
}
function apiError(code, message) { const error = new Error(errors[code] || message || "操作失败，请重试。"); error.code = code; return error; }
async function api(path, body, authenticated = false) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (authenticated) headers.Authorization = "Bearer " + state.token;
  let response;
  try {
    response = await fetch(path, { method: body === undefined ? "GET" : "POST", headers,
      body: body === undefined ? undefined : JSON.stringify(body), credentials: "omit", cache: "no-store",
      redirect: "error", signal: AbortSignal.timeout(10000) });
  } catch { throw apiError("NETWORK_ERROR", "无法连接本地服务。若刚才正在保存，请刷新数据确认操作结果。"); }
  let value;
  try { value = await response.json(); } catch { throw apiError("INVALID_RESPONSE", "本地服务返回了无法读取的数据。"); }
  if (!response.ok || !value.ok) throw apiError(value.error?.code, value.error?.message);
  return value.result === undefined ? value : value.result;
}
async function loadHall() {
  const result = await api("/api/local/dispatch", { operation: "hall.get" }, true);
  state.hall = result.data; state.revision = result.revision;
  if (!state.hall.inventory.items.some((item) => item.id === state.selected)) state.selected = null;
  render();
}
function busy(value) {
  state.busy = value;
  document.querySelectorAll("button").forEach((button) => {
    if (value) { button.dataset.wasDisabled = String(button.disabled); button.disabled = true; }
    else if (button.dataset.wasDisabled !== undefined) { button.disabled = button.dataset.wasDisabled === "true"; delete button.dataset.wasDisabled; }
  });
}
async function perform(action) {
  if (state.busy) return;
  busy(true);
  try { await action(); }
  catch (error) {
    if (error.code === "STALE_REVISION" && state.token) { try { await loadHall(); } catch {} }
    if (error.code === "UNAUTHORIZED" && state.token) signOut();
    toast(error.message, true);
  } finally { busy(false); }
}
async function mutate(operation, payload, message) {
  return perform(async () => {
    await api("/api/local/dispatch", { operation, payload, request_id: crypto.randomUUID(), expected_revision: state.revision }, true);
    await loadHall(); toast(message || "操作已保存");
  });
}
function setMode(mode) {
  state.mode = mode; const register = mode === "register";
  $("auth-title").textContent = register ? "创建本地账号" : "欢迎回来";
  $("auth-description").textContent = register ? "为你的本地存档创建独立账号" : "登录你的独立本地账号";
  $("auth-submit").replaceChildren(document.createTextNode(register ? "注册并进入 " : "登录本地入口 "), node("span", { text: "→" }));
  $("confirm-field").hidden = !register; $("password-confirm").required = register;
  $("password").autocomplete = register ? "new-password" : "current-password";
  for (const tab of ["login", "register"]) { $(tab + "-tab").classList.toggle("active", tab === mode); $(tab + "-tab").setAttribute("aria-selected", String(tab === mode)); }
  $("auth-error").hidden = true;
}
function signOut() {
  state.token = null; state.username = ""; state.hall = null; state.revision = null; state.selected = null;
  $("app-screen").hidden = true; $("auth-screen").hidden = false; $("password").value = ""; $("password-confirm").value = "";
  $("password-form").reset(); setMode("login");
}
function go(view) {
  state.view = view;
  for (const name of ["overview", "inventory", "quests", "account"]) $(name + "-view").hidden = name !== view;
  document.querySelectorAll(".nav").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  $("page-title").textContent = { overview: "总览", inventory: "仓库", quests: "任务", account: "账号设置" }[view];
}
function render() {
  if (!state.hall) return;
  const { profile, inventory, quests } = state.hall;
  $("account-name").textContent = state.username; $("welcome-name").textContent = state.username;
  $("avatar").textContent = Array.from(state.username)[0]?.toUpperCase() || "L";
  $("money").textContent = profile.money.toLocaleString("zh-CN"); $("xp").textContent = profile.xp.toLocaleString("zh-CN");
  $("item-count").textContent = inventory.items.reduce((sum, item) => sum + item.quantity, 0);
  $("quest-count").textContent = quests.filter((quest) => ["accepted", "completed"].includes(quest.status)).length;
  $("quest-preview").replaceChildren(...quests.slice(0, 2).map((quest) => node("div", { className: "preview-row" }, [
    node("span", { className: "preview-icon", text: "☷" }), node("div", {}, [node("strong", { text: pretty(quest.definition.name) }),
      node("small", { text: quest.progress.reduce((sum, n) => sum + n, 0) + " / " + quest.definition.objectives.reduce((sum, objective) => sum + objective.count, 0) + " 目标进度" })]),
    node("span", { className: "state-chip", text: statusNames[quest.status] })])));
  renderInventory(); renderQuests(); renderDetails();
}
function selectItem(id) {
  state.selected = id; renderInventory(); renderDetails();
}
function itemButton(item, equipment = false) {
  const kind = item.template_id === "local_rifle" ? "rifle" : item.template_id === "local_ammo" ? "ammo" : "medkit";
  const symbol = { rifle: "╾━╤", ammo: "▥", medkit: "✚" }[kind];
  const element = node("button", { className: equipment ? "equipment-item" : "inventory-item " + kind + (state.selected === item.id ? " selected" : ""),
    type: "button", "aria-label": itemName(item.template_id) + "，数量 " + item.quantity,
    onClick: () => selectItem(item.id) }, [node("span", { className: "item-symbol", text: symbol }),
    node("span", { className: "item-label", text: itemName(item.template_id) }), node("span", { className: "item-quantity", text: "×" + item.quantity })]);
  element.draggable = true;
  element.addEventListener("dragstart", (event) => { event.dataTransfer.setData("text/plain", item.id); event.dataTransfer.effectAllowed = "move"; state.selected = item.id; renderDetails(); });
  return element;
}
function renderInventory() {
  const inventory = state.hall.inventory;
  const order = ["warehouse", "backpack", "equipment"];
  $("containers").replaceChildren(...order.map((name) => {
    const shape = inventory.containers.find((container) => container.name === name);
    if (!shape) return node("div");
    const items = inventory.items.filter((item) => item.container === name);
    const panel = node("section", { className: "container-panel" });
    panel.append(node("div", { className: "container-header" }, [node("h3", { text: containerNames[name] }),
      node("small", { text: name === "equipment" ? "PRIMARY SLOT" : shape.width + " × " + shape.height })]));
    if (name === "equipment") { panel.append(items.length ? itemButton(items[0], true) : node("div", { className: "empty-equipment", text: "主武器栏为空" })); return panel; }
    const grid = node("div", { className: "inventory-grid", "aria-label": containerNames[name] + "物品格子" });
    grid.style.setProperty("--cols", shape.width); grid.style.setProperty("--rows", shape.height); grid.style.setProperty("--ratio", shape.width + " / " + shape.height);
    for (let y = 0; y < shape.height; y++) for (let x = 0; x < shape.width; x++) {
      const cell = node("button", { className: "cell", type: "button", "aria-label": containerNames[name] + "第 " + (x + 1) + " 列第 " + (y + 1) + " 行",
        onClick: () => { if (state.selected) moveSelected(name, x, y); else toast("请先选择一件物品"); } });
      cell.style.gridColumn = String(x + 1); cell.style.gridRow = String(y + 1); grid.append(cell);
    }
    for (const item of items) {
      const definition = state.catalog.items[item.template_id];
      const width = item.rotated ? definition.height : definition.width; const height = item.rotated ? definition.width : definition.height;
      const element = itemButton(item); element.style.gridColumn = (item.x + 1) + " / span " + width; element.style.gridRow = (item.y + 1) + " / span " + height; grid.append(element);
    }
    grid.addEventListener("dragover", (event) => { event.preventDefault(); event.dataTransfer.dropEffect = "move"; });
    grid.addEventListener("drop", (event) => {
      event.preventDefault(); const id = event.dataTransfer.getData("text/plain");
      if (!inventory.items.some((item) => item.id === id)) return;
      state.selected = id; const rect = grid.getBoundingClientRect();
      const x = Math.max(0, Math.min(shape.width - 1, Math.floor((event.clientX - rect.left) / rect.width * shape.width)));
      const y = Math.max(0, Math.min(shape.height - 1, Math.floor((event.clientY - rect.top) / rect.height * shape.height)));
      moveSelected(name, x, y);
    });
    panel.append(grid); return panel;
  }));
}
function selectedItem() { return state.hall?.inventory.items.find((item) => item.id === state.selected); }
function renderDetails() {
  const item = selectedItem(); $("move-form").hidden = !item;
  $("selected-title").textContent = item ? itemName(item.template_id) : "选择一件物品";
  $("selected-info").textContent = item ? "数量 " + item.quantity + " · " + containerNames[item.container] + (item.equipped_slot ? " · 主武器栏" : " · 第 " + (item.x + 1) + " 列第 " + (item.y + 1) + " 行") : "点击格子中的物品查看和操作。";
  if (!item) return;
  $("move-container").value = item.container === "equipment" ? "warehouse" : item.container;
  $("move-x").value = item.x + 1; $("move-y").value = item.y + 1; $("move-rotated").checked = Boolean(item.rotated);
  $("split-section").hidden = item.quantity <= 1 || item.container === "equipment"; $("split-quantity").max = item.quantity - 1;
  $("equip-item").hidden = !state.catalog.items[item.template_id].slots.includes("primary") || item.container === "equipment";
}
function moveSelected(container, x, y) {
  const item = selectedItem(); if (!item) return;
  mutate("inventory.move", { instance_id: item.id, container, x, y, rotated: $("move-rotated").checked }, "物品位置已保存");
}
function movePayload() { return { instance_id: state.selected, container: $("move-container").value,
  x: Number($("move-x").value) - 1, y: Number($("move-y").value) - 1, rotated: $("move-rotated").checked }; }
function questAction(text, operation, questId, className = "primary") {
  return node("button", { className, type: "button", text, onClick: () => mutate(operation, { quest_id: questId }, "任务进度已保存") });
}
function renderQuests() {
  $("quest-list").replaceChildren(...state.hall.quests.map((quest) => {
    const definition = quest.definition;
    const card = node("article", { className: "quest-card", "data-quest-id": quest.quest_id });
    card.append(node("div", { className: "quest-card-header" }, [node("h3", { text: pretty(definition.name) }), node("span", { className: "state-chip", text: statusNames[quest.status] })]));
    definition.objectives.forEach((objective, index) => {
      const progress = quest.progress[index]; const remaining = objective.count - progress;
      const row = node("div", { className: "objective" });
      const label = objective.kind === "submit" ? "提交 " + itemName(objective.target) : "击败本地训练目标";
      row.append(node("div", { className: "objective-top" }, [node("span", { text: label }), node("span", { text: progress + " / " + objective.count })]));
      const fill = node("div", { className: "progress-fill" }); fill.style.width = Math.min(100, progress / objective.count * 100) + "%";
      row.append(node("div", { className: "progress-track" }, [fill]));
      if (quest.status === "accepted" && objective.kind === "submit" && remaining > 0) {
        const eligible = state.hall.inventory.items.filter((item) => item.template_id === objective.target && !item.equipped_slot);
        if (eligible.length) {
          const select = node("select", { "aria-label": "选择提交物品" }, eligible.map((item) => node("option", { value: item.id, text: containerNames[item.container] + " · " + itemName(item.template_id) + " ×" + item.quantity })));
          const amount = node("input", { type: "number", min: 1, max: Math.min(remaining, eligible[0].quantity), value: Math.min(remaining, eligible[0].quantity), "aria-label": "提交数量" });
          select.addEventListener("change", () => { const max = Math.min(remaining, eligible.find((item) => item.id === select.value).quantity); amount.max = max; amount.value = max; });
          row.append(node("div", { className: "submit-row" }, [select, amount, node("button", { className: "secondary", text: "提交物品", type: "button",
            onClick: () => { const quantity = Number(amount.value); if (!Number.isInteger(quantity) || quantity < 1 || quantity > Number(amount.max)) { toast("请填写有效的提交数量", true); return; }
              mutate("quests.submit", { quest_id: quest.quest_id, objective_index: index, instance_id: select.value, quantity }, "补给已提交，任务进度已保存"); } })]));
        } else row.append(node("p", { className: "quest-hint", text: "仓库或背包中没有符合目标的物品。" }));
      }
      if (objective.kind !== "submit" && quest.status !== "claimed") row.append(node("p", { className: "quest-hint", text: "此目标需要本地战斗服务记录事件；战斗服务尚未接入。" }));
      card.append(row);
    });
    const reward = definition.reward || {};
    const rewards = node("div", { className: "rewards" }, [node("span", { text: "奖励 " + (reward.money || 0).toLocaleString("zh-CN") + " 余额" }), node("span", { text: "+" + (reward.xp || 0) + " 经验" }),
      ...(reward.items || []).map((item) => node("span", { text: itemName(item.template_id) + " ×" + item.quantity }))]);
    const actions = node("div", { className: "quest-actions" });
    if (quest.status === "available") actions.append(questAction("领取任务 →", "quests.accept", quest.quest_id));
    if (quest.status === "accepted") {
      actions.append(questAction("放弃", "quests.abandon", quest.quest_id, "quiet"));
      if (definition.objectives.every((objective, index) => quest.progress[index] >= objective.count)) actions.append(questAction("完成任务 →", "quests.complete", quest.quest_id));
    }
    if (quest.status === "completed") actions.append(questAction("领取奖励 →", "quests.claim", quest.quest_id));
    if (quest.status === "locked") actions.append(node("span", { className: "muted", text: "完成前置任务后解锁" }));
    card.append(node("div", { className: "quest-footer" }, [rewards, actions])); return card;
  }));
}

$("endpoint").textContent = location.host;
$("login-tab").addEventListener("click", () => setMode("login")); $("register-tab").addEventListener("click", () => setMode("register"));
$("auth-form").addEventListener("submit", (event) => {
  event.preventDefault(); if (state.busy) return;
  $("auth-error").hidden = true;
  if (state.mode === "register" && $("password").value !== $("password-confirm").value) { $("auth-error").textContent = "两次密码输入不一致。"; $("auth-error").hidden = false; return; }
  perform(async () => {
    try {
      const result = await api("/api/local/" + state.mode, { username: $("username").value.trim(), password: $("password").value });
      state.token = result.session; state.username = result.account.username;
      $("password").value = ""; $("password-confirm").value = "";
      state.catalog = await api("/api/local/catalog"); await loadHall();
      $("auth-screen").hidden = true; $("app-screen").hidden = false; go("overview");
    } catch (error) {
      if (state.token) { try { await api("/api/local/logout", {}, true); } catch {} signOut(); }
      $("auth-error").textContent = error.message; $("auth-error").hidden = false;
    }
  });
});
document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => go(button.dataset.view)));
document.querySelectorAll("[data-go]").forEach((button) => button.addEventListener("click", () => go(button.dataset.go)));
$("refresh").addEventListener("click", () => perform(async () => { await loadHall(); toast("数据已刷新"); }));
for (const id of ["logout", "logout-account"]) $(id).addEventListener("click", () => perform(async () => { await api("/api/local/logout", {}, true); signOut(); toast("已退出本地账号"); }));
$("move-form").addEventListener("submit", (event) => { event.preventDefault(); if (state.selected) mutate("inventory.move", movePayload(), "物品位置已保存"); });
$("split-item").addEventListener("click", () => {
  const quantity = Number($("split-quantity").value); const item = selectedItem();
  if (!item || !Number.isInteger(quantity) || quantity < 1 || quantity >= item.quantity) { toast("拆分数量必须小于当前堆叠数量", true); return; }
  mutate("inventory.split", { ...movePayload(), quantity }, "堆叠已拆分");
});
$("equip-item").addEventListener("click", () => { if (state.selected) mutate("inventory.equip", { instance_id: state.selected, slot: "primary" }, "主武器已装备"); });
$("password-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if ($("new-password").value !== $("new-password-confirm").value) { toast("两次新密码输入不一致", true); return; }
  perform(async () => {
    const result = await api("/api/local/change-password", { current_password: $("current-password").value, new_password: $("new-password").value }, true);
    state.token = result.session; $("password-form").reset(); toast("本地密码已更新");
  });
});
async function health() {
  try {
    const value = await api("/healthz"); state.online = value.service === "persistent_local_backend";
  } catch { state.online = false; }
  $("service-label").textContent = state.online ? "本地服务在线" : "本地服务连接中断";
  $("service-dot").className = "dot " + (state.online ? "good" : "bad");
}
health(); setInterval(health, 15000);
