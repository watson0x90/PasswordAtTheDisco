// Small accessible info marker: a hoverable "ⓘ" showing a definition (native title;
// no deps). Sits inline next to a label/header.
export function InfoTip({ text }: { text: string }) {
  return (
    <span className="infotip" title={text} aria-label={text} role="img">ⓘ</span>
  )
}
