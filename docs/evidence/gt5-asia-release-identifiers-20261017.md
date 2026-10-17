# GT5 Asia release identifiers

The GT5 region inventory previously listed `BCAS-20164` as the Asian public
release ID. The available records point to two different identifiers, with
catalogs using different field labels:

- The GT5 Modding Hub lists `BCAS-20151` as the Asia version of the main GT5
  build and has a per-version executable/update inventory for it.
- Retroplace labels `BCAS-20164` as the Asian packaging product code and leaves the media product code unknown.
- GameFAQs lists `BCAS-20164` in its release table's `Product ID` column, so the
  public catalogs do not agree on the identifier's exact role.

The inventory records `BCAS-20151` under Asia release IDs and `BCAS-20164`
under Asia packaging product codes, following the explicit packaging label on
Retroplace. This classification is public release metadata only; it does not
establish executable identity or prove that either identifier is interchangeable
with the other. `BCUS-98114` remains the only locally verified GT5 executable
profile in the repository.

Sources:

- GT5 Modding Hub: <https://nenkai.github.io/gt-modding-hub/builds/gt5/>
- Retroplace Asia listing: <https://www.retroplace.com/de/spiele/113038--gran-turismo-5>
- GameFAQs release data: <https://gamefaqs.gamespot.com/ps3/941103-gran-turismo-5/data>

Next evidence needed before adding an Asian executable profile: a legally
obtained local `BCAS-20151` ELF/container whose identity can be independently
verified. No binary was available for this update.
