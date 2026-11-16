import { act } from "react";
import { fireEvent, render, screen, within } from "../test-utils";
import { I18nProvider } from "../i18n";
import { DataTable, type Column } from "../components/DataTable";

type Row = { id: string; name: string; tags: string[] };
const rows: Row[] = [
  { id: "1", name: "Target 10", tags: ["blue", "prod"] },
  { id: "2", name: "Target 2", tags: ["green"] },
];
const columns: Column<Row>[] = [
  { key: "name", header: "Name", render: (row) => row.name, values: (row) => [row.name] },
  { key: "tags", header: "Tags", render: (row) => row.tags.join(", "), values: (row) => row.tags },
];

describe("DataTable", () => {
  it("keeps the existing table markup while sorting and filtering through TanStack Table", async () => {
    render(<I18nProvider><DataTable rows={rows} columns={columns} rowKey={(row) => row.id} /></I18nProvider>);
    const table = screen.getByRole("table");
    expect(table.querySelectorAll("thead th")).toHaveLength(2);
    expect(within(table).getAllByRole("row").map((row) => row.textContent)).toEqual([
      "NameTags", "Target 10blue, prod", "Target 2green",
    ]);

    act(() => fireEvent.click(screen.getByRole("button", { name: "Name" })));
    expect(within(table).getAllByRole("row").map((row) => row.textContent)).toEqual([
      "NameTags", "Target 2green", "Target 10blue, prod",
    ]);

    act(() => fireEvent.click(screen.getAllByRole("button", { name: "Filter" })[1]));
    const green = await screen.findByLabelText("green");
    act(() => fireEvent.click(green));
    expect(within(table).getAllByRole("row").map((row) => row.textContent)).toEqual([
      "NameTags", "Target 2green",
    ]);
  });
});
