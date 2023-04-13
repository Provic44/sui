// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { expect } from '../fixtures';

import type { Page, BrowserContext } from '@playwright/test';

export async function demoDappConnect(
    page: Page,
    demoPageUrl: string,
    context: BrowserContext
) {
    await page.goto(demoPageUrl);
    const newWalletPage = context.waitForEvent('page');
    await page.getByRole('button', { name: 'Connect' }).click();
    const walletPage = await newWalletPage;
    await walletPage.waitForLoadState();
    await walletPage.getByRole('button', { name: 'Continue' }).click();
    await walletPage.getByRole('button', { name: 'Connect' }).click();
    await page.waitForSelector('.account');
    await expect((await page.locator('.account').all()).length).toBe(1);
}
