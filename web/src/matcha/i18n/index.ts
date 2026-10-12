/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
// Fork-only UI strings (抹茶公益站). They live here instead of
// web/src/i18n/locales/*.json so the daily rebase onto upstream never has to
// merge fork keys into upstream's locale files, which upstream rewrites often.
// Bundles are merged over upstream's, so a key defined here wins.
import i18n from 'i18next'

import en from './locales/en.json'
import fr from './locales/fr.json'
import ja from './locales/ja.json'
import ru from './locales/ru.json'
import vi from './locales/vi.json'
import zhTW from './locales/zh-TW.json'
import zhCN from './locales/zh.json'

export const matchaTranslations: Record<string, Record<string, string>> = {
  en,
  zhCN,
  fr,
  ru,
  ja,
  vi,
  zhTW,
}

for (const [lng, bundle] of Object.entries(matchaTranslations)) {
  i18n.addResourceBundle(lng, 'translation', bundle, true, true)
}
