// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ChevronDown12 } from '@mysten/icons';
import { type ReactNode, useMemo, useState } from 'react';

import { Text } from './Text';

interface ExpandableListProps {
    children: ReactNode[];
    defaultItemsToShow?: number;
}

export function ExpandableList({
    children,
    defaultItemsToShow = 3,
}: ExpandableListProps) {
    const [showAll, setShowAll] = useState(false);
    const items = useMemo(
        () => (showAll ? children : children.slice(0, defaultItemsToShow)),
        [showAll, children, defaultItemsToShow]
    );

    const handleShowAllClick = () =>
        setShowAll((prevShowAll: boolean) => !prevShowAll);

    return (
        <div className="flex flex-col gap-4">
            {items.map((item, index) => (
                <div key={index}>{item}</div>
            ))}
            {children.length > defaultItemsToShow && (
                <button
                    onClick={handleShowAllClick}
                    type="button"
                    className="mt-2 flex cursor-pointer items-center gap-1 text-steel hover:text-steel-dark"
                >
                    <Text variant="bodySmall/medium">
                        {showAll ? 'Show Less' : 'Show All'}
                    </Text>
                    <ChevronDown12
                        height={12}
                        width={12}
                        className={showAll ? 'rotate-180' : ''}
                    />
                </button>
            )}
        </div>
    );
}
