import argparse
import os
import pandas as pd

def collect_results(experiments_dir: str) -> pd.DataFrame:
    rows = []
    for protocol in sorted(os.listdir(experiments_dir)):
        protocol_dir = os.path.join(experiments_dir, protocol)
        if not os.path.isdir(protocol_dir):
            continue
        for n_party in sorted(os.listdir(protocol_dir)):
            n_party_dir = os.path.join(protocol_dir, n_party)
            if not os.path.isdir(n_party_dir):
                continue
            for n_constraint in sorted(os.listdir(n_party_dir)):
                constraint_dir = os.path.join(n_party_dir, n_constraint)
                if not os.path.isdir(constraint_dir):
                    continue
                for party in sorted(os.listdir(constraint_dir)):
                    party_dir = os.path.join(constraint_dir, party)
                    if not os.path.isdir(party_dir):
                        continue
                    for filename in os.listdir(party_dir):
                        if not filename.endswith(".csv"):
                            continue
                        phase = filename[:-4]
                        file_path = os.path.join(party_dir, filename)
                        df = pd.read_csv(file_path)
                        if df.empty:
                            continue
                        data = df.iloc[0].to_dict()
                        data.update(
                            {
                                "protocol": protocol,
                                "n_parties": int(n_party),
                                "n_constraints": int(n_constraint),
                                "party": party,
                                "phase": phase,
                            }
                        )
                        rows.append(data)
    return pd.DataFrame(rows)

def aggregate_results(df: pd.DataFrame) -> pd.DataFrame:
    numeric_cols = [
        "Field Elements",
        "G1 Elements",
        "G2 Elements",
        "Bytes",
        "Total Time",
    ]
    df[numeric_cols] = df[numeric_cols].apply(pd.to_numeric)
    grouped = (
        df.groupby(["protocol", "n_parties", "n_constraints", "phase"])[numeric_cols]
        .median()
        .reset_index()
    )
    grouped["title"] = grouped.apply(
        lambda r: f"{r['protocol']}/{r['n_parties']}/{r['n_constraints']}",
        axis=1,
    )
    return grouped[["title", "phase"] + numeric_cols]

def main() -> None:
    parser = argparse.ArgumentParser(description="Compile experiment statistics")
    parser.add_argument(
        "--experiments-dir",
        default="../collaborative-cp-snarks/experiments",
        help="Path to the experiments directory",
    )
    parser.add_argument(
        "--output",
        default="compiled_results_median.csv",
        help="CSV file to write combined results (using medians)",
    )
    args = parser.parse_args()
    df = collect_results(args.experiments_dir)
    aggregated = aggregate_results(df)
    aggregated.to_csv(args.output, index=False)

if __name__ == "__main__":
    main()
