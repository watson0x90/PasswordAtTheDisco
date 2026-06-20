import { pageWindow, type Page } from "../sortPage"

// The pagination bar. Always shows the count + a Rows size selector; the
// Prev/Next/number strip is omitted when there is only one page.
export function Pager<T>({ page, sizes = [25, 50, 100] }: { page: Page<T>; sizes?: number[] }) {
  const nums = pageWindow(page.page, page.pageCount)
  return (
    <div className="pager">
      <div className="pager-info">
        <span>
          Showing {page.start.toLocaleString()}–{page.end.toLocaleString()} of {page.total.toLocaleString()}
        </span>
        <label className="pager-size">
          Rows:
          <select className="search" value={page.pageSize} onChange={(e) => page.setPageSize(Number(e.target.value))}>
            {sizes.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
      </div>
      {page.pageCount > 1 && (
        <div className="pager-nav">
          <button className="pager-btn" disabled={page.page <= 1} onClick={() => page.setPage(page.page - 1)}>
            ‹ Prev
          </button>
          {nums.map((n, i) =>
            n === "…" ? (
              <span key={`gap-${i}`} className="pager-gap">
                …
              </span>
            ) : (
              <button key={n} className={n === page.page ? "pager-num active" : "pager-num"} onClick={() => page.setPage(n as number)}>
                {n}
              </button>
            ),
          )}
          <button className="pager-btn" disabled={page.page >= page.pageCount} onClick={() => page.setPage(page.page + 1)}>
            Next ›
          </button>
        </div>
      )}
    </div>
  )
}
