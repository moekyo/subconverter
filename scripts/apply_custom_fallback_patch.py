#!/usr/bin/env python3
"""Apply the custom fallback health-check field patch at image build time.

The upstream source tree is intentionally left unchanged in git. This script
patches the checked-out source inside the Docker build context before compiling.
It fails loudly if upstream code moves enough that the expected replacement
anchors are no longer present.
"""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    file_path = ROOT / path
    text = file_path.read_text()
    if new in text:
        print(f"already patched: {path}")
        return
    if old not in text:
        print(f"patch anchor not found: {path}", file=sys.stderr)
        sys.exit(1)
    file_path.write_text(text.replace(old, new, 1))
    print(f"patched: {path}")


def main() -> None:
    replace_once(
        "src/config/proxygroup.h",
        """    Integer Interval = 0;
    Integer Timeout = 0;
    Integer Tolerance = 0;
    BalanceStrategy Strategy = BalanceStrategy::ConsistentHashing;
    Boolean Lazy;
    Boolean DisableUdp;
    Boolean Persistent;
    Boolean EvaluateBeforeUse;
""",
        """    Integer Interval = 0;
    Integer Timeout = 0;
    Integer Tolerance = 0;
    Integer MaxFailedTimes = 0;
    BalanceStrategy Strategy = BalanceStrategy::ConsistentHashing;
    Boolean Lazy;
    Boolean DisableUdp;
    Boolean Persistent;
    Boolean EvaluateBeforeUse;
    String ExpectedStatus;
""",
    )

    replace_once(
        "src/config/binding.h",
        """            case "fallback"_hash:
                conf.Type = ProxyGroupType::Fallback;
                conf.Url = find<String>(v, "url");
                conf.Interval = find<Integer>(v, "interval");
                if(v.contains("evaluate-before-use"))
                    conf.EvaluateBeforeUse = find_or(v, "evaluate-before-use", conf.EvaluateBeforeUse.get());
                break;
""",
        """            case "fallback"_hash:
                conf.Type = ProxyGroupType::Fallback;
                conf.Url = find<String>(v, "url");
                conf.Interval = find<Integer>(v, "interval");
                conf.Tolerance = find_or<Integer>(v, "tolerance", 0);
                if(v.contains("lazy"))
                    conf.Lazy = find_or<bool>(v, "lazy", false);
                if(v.contains("evaluate-before-use"))
                    conf.EvaluateBeforeUse = find_or(v, "evaluate-before-use", conf.EvaluateBeforeUse.get());
                break;
""",
    )

    replace_once(
        "src/config/binding.h",
        """            conf.Timeout = find_or(v, "timeout", 5);
            conf.Proxies = find_or<StrArray>(v, "rule", {});
""",
        """            conf.Timeout = find_or(v, "timeout", 0);
            conf.MaxFailedTimes = find_or<Integer>(v, "max-failed-times", 0);
            if(v.contains("expected-status"))
            {
                if(v.at("expected-status").is_integer())
                    conf.ExpectedStatus = std::to_string(find<Integer>(v, "expected-status"));
                else
                    conf.ExpectedStatus = find<String>(v, "expected-status");
            }
            conf.Proxies = find_or<StrArray>(v, "rule", {});
""",
    )

    replace_once(
        "src/generator/config/subexport.cpp",
        """        case ProxyGroupType::URLTest:
            if(!x.Lazy.is_undef())
                singlegroup["lazy"] = x.Lazy.get();
            [[fallthrough]];
        case ProxyGroupType::Fallback:
            singlegroup["url"] = x.Url;
            if(x.Interval > 0)
                singlegroup["interval"] = x.Interval;
            if(x.Tolerance > 0)
                singlegroup["tolerance"] = x.Tolerance;
            break;
""",
        """        case ProxyGroupType::URLTest:
            [[fallthrough]];
        case ProxyGroupType::Fallback:
            if(!x.Lazy.is_undef())
                singlegroup["lazy"] = x.Lazy.get();
            singlegroup["url"] = x.Url;
            if(x.Interval > 0)
                singlegroup["interval"] = x.Interval;
            if(x.Tolerance > 0)
                singlegroup["tolerance"] = x.Tolerance;
            if(x.Timeout > 0)
                singlegroup["timeout"] = x.Timeout;
            if(x.MaxFailedTimes > 0)
                singlegroup["max-failed-times"] = x.MaxFailedTimes;
            if(!x.ExpectedStatus.empty())
                singlegroup["expected-status"] = x.ExpectedStatus;
            if(!x.EvaluateBeforeUse.is_undef())
                singlegroup["evaluate-before-use"] = x.EvaluateBeforeUse.get();
            break;
""",
    )


if __name__ == "__main__":
    main()
