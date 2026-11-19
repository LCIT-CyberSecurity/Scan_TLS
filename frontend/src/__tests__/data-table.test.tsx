import { act, Profiler, StrictMode } from "react";
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

  it("stops re-rendering once displayed, even when the caller rebuilds rows and columns (LST-30)", async () => {
    // Pages such as Reports build `rows` and `columns` inline. A table that keeps committing on its own creates an endless
    // chain of urgent updates, which starves React transitions: router navigations from that page never commit.
    let commits = 0;
    const page = () => <StrictMode><I18nProvider><Profiler id="table" onRender={() => { commits += 1; }}>
      <DataTable rows={rows.filter(() => true)} columns={columns.map((column) => ({ ...column }))} rowKey={(row) => row.id} />
    </Profiler></I18nProvider></StrictMode>;
    const { rerender } = render(page());
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
    rerender(page());   // the page renders again a moment later, e.g. when its data arrives
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 200)); });
    const settled = commits;
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 300)); });
    expect(commits).toBe(settled);
    expect(commits).toBeLessThan(10);
  });
});
