import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  denyNames,
  findGroup,
  groupPolicyIssues,
  hiddenTools,
  listGroupViews,
  matchesPattern,
  normalizeGroupName,
  normalizeSettings,
  parseKnownRestrictable,
  policyOrphans,
  resolveActiveGroups,
  resolveGroups,
} from "../dist/policy.js";

describe("tool-manager policy", () => {
  it("normalizes malformed settings conservatively", () => {
    assert.deepEqual(normalizeSettings({
      defaultTtlSteps: 3,
      presets: {
        standard: {
          disabled: ["web_fetch", "web_fetch", 42],
          groups: [
            { id: "MCP", label: "GitHub tools", patterns: ["mcp__*"], ttlSteps: 4 },
            { id: "mcp", patterns: ["ignored"] },
            { name: "empty", patterns: [] },
          ],
        },
      },
    }), {
      presets: {
        standard: {
          disabled: ["web_fetch"],
          groups: [
            { name: "MCP", description: "GitHub tools", patterns: ["mcp__*"] },
            { name: "empty", patterns: [] },
          ],
        },
      },
    });
  });

  it("matches exact names and wildcard groups", () => {
    assert.equal(matchesPattern("mcp__github__issue", "mcp__*"), true);
    assert.equal(matchesPattern("read", "read"), true);
    assert.equal(matchesPattern("grep", "read"), false);
    assert.equal(matchesPattern("web_fetch", "web_*"), true);
    assert.equal(matchesPattern("web-fetch", "web_*"), false);
  });

  it("resolves group membership and hidden union", () => {
    const policy = {
      disabled: ["web_fetch"],
      groups: [{ name: "mcp", patterns: ["mcp__*"] }],
    };
    const names = ["read", "web_fetch", "mcp__git__status", "mcp__db__query"];
    assert.deepEqual(resolveGroups(policy, names)[0]?.tools, [
      "mcp__git__status",
      "mcp__db__query",
    ]);
    assert.deepEqual([...hiddenTools(policy, names)], [
      "web_fetch",
      "mcp__git__status",
      "mcp__db__query",
    ]);
  });

  it("keeps exposed group tools visible unless explicitly disabled", () => {
    const policy = {
      disabled: ["mcp__git__status"],
      groups: [{ name: "mcp", patterns: ["mcp__*"] }],
    };
    const names = ["read", "web_fetch", "mcp__git__status", "mcp__db__query"];
    assert.deepEqual(denyNames(policy, names, new Set(["mcp"])), [
      "mcp__git__status",
    ]);
    assert.deepEqual(denyNames(policy, names, new Set()), [
      "mcp__git__status",
      "mcp__db__query",
    ]);
  });

  it("never denies discovery or PTC transport even if a policy names them", () => {
    const policy = {
      disabled: ["tool_list", "run_code", "read"],
      groups: [{ name: "all", patterns: ["*"] }],
    };
    assert.deepEqual(denyNames(policy, ["read", "tool_list", "run_code", "write"], new Set()), [
      "read",
      "write",
    ]);
  });

  it("hides globally registered tool_list when a preset has no active groups", () => {
    assert.deepEqual(denyNames(
      { disabled: [], groups: [] },
      ["read", "tool_list", "write"],
      new Set(),
    ), ["tool_list"]);
    assert.deepEqual(denyNames(
      { disabled: [], groups: [{ name: "empty", patterns: ["gone"] }] },
      ["read", "tool_list", "write"],
      new Set(),
    ), ["tool_list"]);
  });

  it("keeps empty groups visible as invalid configuration", () => {
    const policy = {
      disabled: ["gone", "read"],
      groups: [{ name: "mcp", patterns: [] }],
    };
    assert.deepEqual(policyOrphans(policy, ["read", "write"]), {
      disabled: ["gone"],
      emptyGroups: ["mcp"],
    });
  });

  it("marks opened groups without listing tools", () => {
    const groups = [{
      name: "GitHub MCP",
      description: "GitHub tools",
      patterns: ["mcp__*"],
      tools: Array.from({ length: 30 }, (_, i) => `mcp__s__t${i}`),
    }];
    const listed = listGroupViews(groups, new Set(["GitHub MCP"]));
    assert.equal(listed.length, 1);
    assert.equal(listed[0]?.name, "GitHub MCP");
    assert.equal(listed[0]?.description, "GitHub tools");
    assert.equal(listed[0]?.exposed, true);
  });

  it("resolves only non-empty active groups and excludes discovery transports", () => {
    const policy = {
      disabled: [],
      groups: [
        { name: "all", patterns: ["*"] },
        { name: "empty", patterns: ["gone"] },
      ],
    };
    assert.deepEqual(resolveActiveGroups(
      policy,
      ["read", "tool_list", "run_code"],
    ).map((group) => ({ name: group.name, tools: group.tools })), [
      { name: "all", tools: ["read"] },
    ]);
    assert.deepEqual(resolveActiveGroups(
      { disabled: ["read"], groups: [{ name: "disabled only", patterns: ["read"] }] },
      ["read", "tool_list"],
    ), []);
  });

  it("assigns overlapping tools to the first group and reports policy conflicts", () => {
    const policy = {
      disabled: ["web_fetch"],
      groups: [
        { name: "Web", patterns: ["web_*"] },
        { name: "Search", patterns: ["web_search"] },
        { name: "Fetch", patterns: ["web_fetch"] },
      ],
    };
    assert.deepEqual(resolveActiveGroups(policy, ["web_search", "web_fetch"])
      .map((group) => ({ name: group.name, tools: group.tools })), [
      { name: "Web", tools: ["web_search"] },
    ]);
    assert.deepEqual(groupPolicyIssues(policy, ["web_search", "web_fetch"]), {
      emptyGroups: ["Fetch"],
      disabledMembers: [{ tool: "web_fetch", groups: ["Web"] }, { tool: "web_fetch", groups: ["Fetch"] }],
      duplicateMembers: [
        { tool: "web_search", groups: ["Web", "Search"] },
        { tool: "web_fetch", groups: ["Web", "Fetch"] },
      ],
    });
  });

  it("finds a group by name case-insensitively", () => {
    const groups = [{ name: "GitHub MCP", patterns: [], tools: ["mcp__a"] }];
    assert.equal(findGroup(groups, " github mcp ")?.name, "GitHub MCP");
    assert.equal(findGroup(groups, "other"), undefined);
  });

  it("normalizes group names without truncating or ascii-slugifying", () => {
    const longName = `搜索工具${"长".repeat(200)}`;
    assert.equal(normalizeGroupName(" GitHub MCP "), "GitHub MCP");
    assert.equal(normalizeGroupName("搜索工具"), "搜索工具");
    assert.equal(normalizeGroupName(`  ${longName}  `), longName);
  });

  it("parses restrict() unknown-name diagnostics", () => {
    const error = new Error('tools.restrict() names unknown global tool "gone"; known global tools: read, write');
    assert.deepEqual([...(parseKnownRestrictable(error) ?? [])], ["read", "write"]);
    assert.equal(parseKnownRestrictable(new Error("boom")), undefined);
  });

  describe("alwaysOpen groups", () => {
    const names = ["read", "web_fetch", "tool_list", "mcp__git__status", "mcp__db__query"];

    it("never hides the members of an always-open group", () => {
      const policy = {
        disabled: [],
        groups: [{ name: "mcp", patterns: ["mcp__*"], alwaysOpen: true }],
      };
      assert.deepEqual(denyNames(policy, names, new Set()), []);
      assert.deepEqual(denyNames(policy, names, new Set(["mcp"])), []);
    });

    it("keeps an explicitly disabled tool hidden inside an always-open group", () => {
      const policy = {
        disabled: ["mcp__git__status"],
        groups: [{ name: "mcp", patterns: ["mcp__*"], alwaysOpen: true }],
      };
      assert.deepEqual(denyNames(policy, names, new Set()), ["mcp__git__status"]);
    });

    it("changes nothing when the flag is absent, false, or not a boolean", () => {
      const closed = {
        disabled: [],
        groups: [{ name: "mcp", patterns: ["mcp__*"] }],
      };
      assert.deepEqual(denyNames(closed, names, new Set()), ["mcp__git__status", "mcp__db__query"]);
      assert.deepEqual(
        denyNames({ ...closed, groups: [{ name: "mcp", patterns: ["mcp__*"], alwaysOpen: false }] }, names, new Set()),
        ["mcp__git__status", "mcp__db__query"],
      );
      assert.deepEqual(
        denyNames({ ...closed, groups: [{ name: "mcp", patterns: ["mcp__*"], alwaysOpen: "yes" }] }, names, new Set()),
        ["mcp__git__status", "mcp__db__query"],
      );
    });

    it("normalizes only a literal true and leaves the stored policy byte-identical", () => {
      const normalized = normalizeSettings({
        presets: {
          alpha: { disabled: [], groups: [{ name: "a", patterns: ["read"], alwaysOpen: true }] },
          beta: { disabled: [], groups: [{ name: "b", patterns: ["read"], alwaysOpen: "yes" }] },
          gamma: { disabled: [], groups: [{ name: "c", patterns: ["read"], alwaysOpen: false }] },
          delta: { disabled: [], groups: [{ name: "d", patterns: ["read"], alwaysOpen: 1 }] },
          epsilon: { disabled: [], groups: [{ name: "e", patterns: ["read"] }] },
          zeta: { disabled: [], groups: [{ name: "f", patterns: ["read"], alwaysOpen: null }] },
        },
      });
      assert.deepEqual(normalized.presets.alpha, {
        disabled: [],
        groups: [{ name: "a", patterns: ["read"], alwaysOpen: true }],
      });
      for (const presetId of ["beta", "gamma", "delta", "epsilon", "zeta"]) {
        assert.deepEqual(
          normalized.presets[presetId],
          { disabled: [], groups: [{ name: normalized.presets[presetId].groups[0].name, patterns: ["read"] }] },
        );
        assert.equal(Object.hasOwn(normalized.presets[presetId].groups[0], "alwaysOpen"), false);
      }
    });

    it("carries the flag into resolved group views", () => {
      const policy = {
        disabled: [],
        groups: [
          { name: "mcp", description: "MCP tools", patterns: ["mcp__*"], alwaysOpen: true },
          { name: "web", patterns: ["web_*"] },
        ],
      };
      assert.deepEqual(resolveGroups(policy, names), [
        {
          name: "mcp",
          description: "MCP tools",
          patterns: ["mcp__*"],
          tools: ["mcp__git__status", "mcp__db__query"],
          alwaysOpen: true,
        },
        { name: "web", patterns: ["web_*"], tools: ["web_fetch"] },
      ]);
      assert.deepEqual(
        resolveActiveGroups(policy, names).map((group) => [group.name, group.alwaysOpen === true]),
        [["mcp", true], ["web", false]],
      );
    });

    it("reports an always-open group as exposed regardless of exposures", () => {
      const groups = [
        { name: "mcp", description: "MCP tools", patterns: ["mcp__*"], tools: ["mcp__a"], alwaysOpen: true },
        { name: "web", patterns: ["web_*"], tools: ["web_fetch"] },
        { name: "opened", patterns: ["web_search"], tools: ["web_search"] },
      ];
      assert.deepEqual(listGroupViews(groups, new Set()), [
        { name: "mcp", description: "MCP tools", exposed: true },
        { name: "web", exposed: false },
        { name: "opened", exposed: false },
      ]);
      assert.deepEqual(listGroupViews(groups, new Set(["web"])), [
        { name: "mcp", description: "MCP tools", exposed: true },
        { name: "web", exposed: true },
        { name: "opened", exposed: false },
      ]);
    });

    it("still lists an always-open group in the catalog and remains addressable", () => {
      const policy = {
        disabled: [],
        groups: [{ name: "mcp", patterns: ["mcp__*"], alwaysOpen: true }],
      };
      const active = resolveActiveGroups(policy, names);
      assert.deepEqual(active.map((group) => group.name), ["mcp"]);
      assert.equal(findGroup(active, "mcp")?.name, "mcp");
    });
  });
});
